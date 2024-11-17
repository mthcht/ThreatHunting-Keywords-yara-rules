rule Heroinn
{
    meta:
        description = "Detection patterns for the tool 'Heroinn' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Heroinn"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string1 = /\/Heroinn\.git/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string2 = /\/Heroinn\// nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string3 = /\/heroinn_client\// nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string4 = /\/shell\/shell_port\./ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string5 = /\\heroinn_client\\/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string6 = /09480a5f53d380fcec0fd43f60435c4d6ad9d3decca9cfa419614353f1557a48/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string7 = /0x9999997B3deF7b69c09D7a9CA65E5242fb04a764/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string8 = /1HeroYcNYMhjsq8RYCx1stSaRZnQd9B9Eq/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string9 = /4c0700a6f8d222d9b2023a800e0f286fc43e0354ec23ea21f9344adfd2fe12c8/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string10 = /a4cc9799fdba898f24de68be43dff98a9c8a153dbf016fdd042127e4b31bbc34/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string11 = /b23r0\/Heroinn/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string12 = /b23r0\/Heroinn/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string13 = /Heroinn\sFTP/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string14 = /heroinn_client/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string15 = /heroinn_core/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string16 = /heroinn_ftp/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string17 = /heroinn_shell/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string18 = /heroinn_util/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string19 = /HeroinnApp/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string20 = /HeroinnProtocol/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string21 = /HeroinnServerCommand/ nocase ascii wide
        // Description: A cross platform C2/post-exploitation framework implementation by Rust.
        // Reference: https://github.com/b23r0/Heroinn
        $string22 = /th3rd\/heroinn/ nocase ascii wide
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
