rule KeePwn
{
    meta:
        description = "Detection patterns for the tool 'KeePwn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KeePwn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string1 = /\s\-\-bruteforce\s.{0,100}\.kdbx/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string2 = /\s\-\-dump_file\sKeepass\.exe\.dmp/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string3 = /\sKeePwn\.py/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string4 = /\s\-\-plugin\sKeeFarceRebornPlugin\.dll/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string5 = /\/keepwn\.core\./ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string6 = /\/KeePwn\.git/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string7 = /\/KeePwn\.py/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string8 = /\/keepwn\.utils\./ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string9 = "/KeePwn/keepwn/" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string10 = "/KeePwn/tarball/" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string11 = "/KeePwn/zipball/" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string12 = /\/KeePwn\-0\.3\// nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string13 = /\\KeePwn\.py/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string14 = /\\KeePwn\\keepwn\\/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string15 = /\\KeePwn\-0\.3\\/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string16 = /\\KeePwn\-main\\/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string17 = "0971aee212257aba1a537747e492b76aff0020623edb68defd378e8ed069f6a8" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string18 = "161451349be662c5c649be01c670f86b233fb08a1c77c9b720ea08b622d04964" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string19 = "2c71dd5b47601d4b105d8da7007511045dd58f5d71b997290209d55f20dce887" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string20 = "39a9f25d64ef416e4be4fadf6fae1b2169bfeb02501be443e8af1fec17412f60" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string21 = "83803142d36f4e09346394ae2038353977bd16389fd80e09dc7fc1e8850e1365" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string22 = "8793997d31b23280ec1a46ff7fd065a6510ea66fcbf12651583244805e958212" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string23 = "a8fca4711a214b5b154a7a9f31018bff0eb59ddc8dfe8bad04dde7f90972437a" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string24 = "b7b67e33ca53799aa1be6a7aa7677363b8a0e711091bccd2e49f501d5dc22de7" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string25 = /d3lb3\@protonmail\.com/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string26 = "e3bd611e8aa3d18d81944ebdabf51ce9aed8eb414a95ee8eb6d45ca0ebd58003" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string27 = "keepass-password-dumper" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string28 = "KeePwn --" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string29 = "KeePwn parse_dump " nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string30 = "KeePwn plugin " nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string31 = "KeePwn trigger " nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string32 = /KeePwn\sv.{0,100}\s\-\sby\sJulien\sBEDEL/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string33 = /keepwn\.__main__\:main/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string34 = /keepwn\.core\./ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string35 = /keepwn\.core\.parse_dump/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string36 = /keepwn\.core\.plugin/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string37 = /keepwn\.core\.search/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string38 = /keepwn\.core\.trigger/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string39 = /KeePwn\.py\s/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string40 = /keepwn\.utils\./ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string41 = /KeePwn\-main\.zip/ nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string42 = "Orange-Cyberdefense/KeePwn" nocase ascii wide
        // Description: A python tool to automate KeePass discovery and secret extraction
        // Reference: https://github.com/Orange-Cyberdefense/KeePwn
        $string43 = "Orange-Cyberdefense/KeePwn" nocase ascii wide
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
