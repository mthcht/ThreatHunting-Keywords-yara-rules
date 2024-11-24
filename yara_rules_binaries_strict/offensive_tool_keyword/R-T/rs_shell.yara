rule rs_shell
{
    meta:
        description = "Detection patterns for the tool 'rs-shell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rs-shell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string1 = /\/rs\-shell\.exe/ nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string2 = /\/rs\-shell\.git/ nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string3 = "/rs-shell/zipball/" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string4 = "/rs-shell-linux " nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string5 = /\/rs\-shell\-windows\.exe/ nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string6 = /\\https_windows_implant\.rs/ nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string7 = /\\rs\-shell\.exe/ nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string8 = /\\rs\-shell\-windows\.exe/ nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string9 = "0d2f5c4ee9f63b465776329c0ad2c94cbad788db383a0d94c0219a64d7f55d46" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string10 = "1e661c6d9386dfb181a8c538c3f0b6c5531f9986ad0564eee847ac917430403a" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string11 = "2062837ed59e6bfda4b2b98be75c37f17e6f8e9dec7cce754609cd249b4d02e3" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string12 = "32292398eca5d75150f89d07a622728e52302a73573ec7e1a28268dbe5079ac2" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string13 = "3fb111c19e638174ed630c9a9d8d999c1bf62d2308a8284fedad1efab45a7f96" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string14 = "5f01feb0f870564dae6ef4741dc3b0e200517ea1d712d095a67f4c84bc922bea" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string15 = "78d6cc62452627889988e7d1d63675ee70a4cea3657631d55afb62467630c954" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string16 = "831d87d48fde985447d82a0dbde6a720ecb4c882e28af0bde713b6b340e5b8e3" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string17 = "86dd7c02ed1f529e5c2ec48b1da08d2570769caaa8250aaf5c4438e2aa5558a6" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string18 = "8e122c687fec626c06bd82a2141ea1c49b262ed8e6d93b95583dbe46811b1629" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string19 = "b5e8ccde03661cc33cc84e5cfd81badadb23a4d25a4117a92254c029c40d9c5a" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string20 = "b8328fa4f70b5252b4d5850b540953a7766483b7c710f4fef68186662849f040" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string21 = "BlWasp/rs-shell" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string22 = /BlWasp\/syscalls\-rs\.git/ nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string23 = "d4deb85a5856036a50fc97fd185a545ec437604a64c0c0f7dfe9b7c81265558c" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string24 = "db1288eace30cc5f6f942df1596f94ba846ed8fee9772ad68fc45a5efac6d6db" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string25 = "ebc3a8b952bb617b89cf6f807c4e60e23978608dcaa75e381406bd85de984481" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string26 = "f0f1873d2b61cd03c1daa52ec0cb279676b118507c9031e26d132b8f4187b2bd" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string27 = "f81c9762e91fbd65cd1a3ca1098b36cba4c07f1eeebb4476900b312c955e30e0" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string28 = "ff7a51c653501cfce1fd9198391441d7bad21a11bd75a905479682c0a00cb846" nocase ascii wide
        // Description: rust reverse shell
        // Reference: https://github.com/BlWasp/rs-shell
        $string29 = /rs\-shell\.exe\s\-m\s/ nocase ascii wide
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
