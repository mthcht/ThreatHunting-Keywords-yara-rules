rule iodine
{
    meta:
        description = "Detection patterns for the tool 'iodine' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "iodine"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string1 = " install iodine" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string2 = /\.\/iodined/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string3 = /\/iodine\-.{0,100}\-windows\.zip/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string4 = /\/iodine\.exe/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string5 = /\/iodine\.git/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string6 = "/iodine-master/" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string7 = "/ionide " nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string8 = "/sysconfig/iodine-server" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string9 = "/unstable/net/iodine" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string10 = /\\iodine\-.{0,100}\-windows\.zip/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string11 = /\\iodine\.exe/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string12 = /\\iodine\-master\\/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string13 = "00cce05cfc7ac3c284be62e98c8ffb25" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string14 = "3318d1dd3fcab5f3e4ab3cc5b690a3f4" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string15 = "3e3fcf025697ee80f044716eee053848" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string16 = "58d82bca11a41a01d0ddfa7d105e6a48" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string17 = "5bb0b56e047e1453a3695ec0b9478b84" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string18 = "6952343cc4614857f83dbb81247871e7" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string19 = "6f2a53476cbc09bbffe7e07d6e9dd19d" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string20 = "795f2e9d0314898ba5a63bd1fdc5fa18" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string21 = "82d331f75a99d1547e0ccc3c3efd0a7a" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string22 = "890f13ab9ee7ea722baf0ceb3ee561c0" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string23 = "a15bb4faba020d217016fde6e231074a" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string24 = "a201bc3c2d47775b39cd90b32eb390e7" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string25 = "af2d9062b7788fc47385d8c6c645dfa0" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string26 = "Aw8KAw4LDgvZDgLUz2rLC2rPBMC" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string27 = "b18aca1b9e2a9e72cb77960c355d288b" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string28 = "bin/iodine" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string29 = "c01fb08dabbd24b151fe5dfbb0742f7a" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string30 = "cdaee04229c5aefdb806af27910f34d3" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string31 = "dfbc5037fe0229e15f6f15775117aef5" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string32 = "f2a64b4fce0d07eafded5c2125d7d80b" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string33 = "fdbf3b81cd69caf5230d76a8b039fd99" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string34 = /https\:\/\/code\.kryo\.se\/iodine\/iodine\-/ nocase ascii wide
        // Description: tunnel IPv4 over DNS tool
        // Reference: https://github.com/yarrick/iodine
        $string35 = "iodine -" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string36 = "iodine -f " nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string37 = "iodine IP over DNS tunneling client" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string38 = "iodine IP over DNS tunneling server" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string39 = "iodine -v" nocase ascii wide
        // Description: tunnel IPv4 over DNS tool
        // Reference: https://github.com/yarrick/iodine
        $string40 = "iodined -" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string41 = "iodined -c" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string42 = "iodined -f " nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string43 = "iodined -v" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string44 = "iodine-latest/" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string45 = /iodine\-latest\-android\.zip/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string46 = "iodine-latest-win32" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string47 = "iodine-latest-windows" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string48 = /iodine\-server\.service/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string49 = "iodinetestingtesting" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string50 = "ionided " nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string51 = "nfxwi0lomv0gk21unfxgo3dfon0gs1th" nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string52 = /silly\.host\.of\.iodine\.code\.kryo\.se/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string53 = "sudo iodine " nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string54 = /test\-iodine\.log/ nocase ascii wide
        // Description: iodine. iodined - tunnel IPv4 over DNS
        // Reference: https://github.com/yarrick/iodine
        $string55 = "yarrick/iodine" nocase ascii wide
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
