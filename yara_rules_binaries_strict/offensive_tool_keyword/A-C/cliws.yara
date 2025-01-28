rule cliws
{
    meta:
        description = "Detection patterns for the tool 'cliws' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cliws"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string1 = " install cliws"
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string2 = "/cliws -l "
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string3 = "/cliws -l 1000"
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string4 = "/cliws -p "
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string5 = /\/cliws\.exe/ nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string6 = /\/cliws\.git/ nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string7 = /\\cliws\.exe/ nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string8 = "0eed39829e042cf451ff602078fc3ffcbcfff075bbd3c4a33ccd26e44a31a9fa" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string9 = "120ebb7f608e411010824805482f682059e9089a8c8a0ca44ff48e69f8ebd64b" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string10 = "220922e65b5b988f62cd1390f7240ccfa0d8c71e7cfe3d3e6c84ee04a37c9910" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string11 = "252320367dfa2dd13f2da44521a0311d1591a952e81b7997c33f4ead02cff736" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string12 = "2920df6a2de4e198af944c9536c96ebc8e8289bb48792fe52e1d5de1747b41d3" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string13 = "2dfdcda3ae74c0e2e3e65adc1cf65676b9e4cbf1d8832aff955c8bd24ea8d280" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string14 = "2fc0adccdf3683c94c1e6c47274e567d980a576f89e8b9672a98de04528eb348" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string15 = "335d51e8af6d00637461087ad4531061213e38a8bb020796fd67d53b7b01a9c4" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string16 = "4125d5d3a70366096d13f69bbc1c54ec0bde74411783246365759cb2e727a8ff" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string17 = "44f266ce71ff63b838e83e60572bed76e2419411c3dcceec025fe63788491aaf" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string18 = "6e058a47fb0c4d8d6aa409451c6d5491999caee95ae7a3e50ead61d8425272ba" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string19 = "74afc28bb4191086a08bf270410650a7eb9f0401192e2ae7a36cf3b6b0e992df" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string20 = "91c355be49a16620621486c0e50c44aa876c0c86c9de0ce5253102b637d1d7dd" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string21 = "962d6367a3b63dfb6a2db910a70650e218344a5c346beb5b8c4ca29a44d488a9" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string22 = "a33909ee705e9f06d27bbca6b33048e5ce0c7caeb14281b726e0c5a32d8c3a42" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string23 = "a9a231b0e4125b73e4aebf024857c6fd1bcada83dc74c6e328abd54ffa795cf1" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string24 = "ab47f495f2c021122da927499eead371cb128e8eee96ba6e858ba5335e8cab57" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string25 = "b20ef2d01915d91f5da22ad05e14dfa7f04af3c457d3267b2882a8cd9f560faa" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string26 = "b23r0/cliws" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string27 = /b23r0\@foxmail\.com/
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string28 = "bb239dee17aad653557b3c981e16e0622772f560e1a25fedc97639f7431ad77b" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string29 = "ca399318490eb76c9a598f4bfd193dc2281eced18c5ed432a41ef3eb540d673a" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string30 = "cc2db2e4464dfa466d3e4db6ad9c1c4905c26b513230f319e68e94133bd639df" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string31 = "Cliws - Lightweight interactive bind/reverse PTY shell" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string32 = "cliws -r ws://"
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string33 = "e5ce8b2978d87ed5506c7b7dcad0d363c70f64ce5fad4b7e4beb465d60aada58" nocase ascii wide
        // Description: Cross platform interactive bind/reverse PTY shell
        // Reference: https://github.com/b23r0/cliws
        $string34 = "f42046227f0809a1311ad6b7cd6a904b84343ef4ecb426598ce356199720594d" nocase ascii wide
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
