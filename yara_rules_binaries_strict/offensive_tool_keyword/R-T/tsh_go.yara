rule tsh_go
{
    meta:
        description = "Detection patterns for the tool 'tsh-go' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tsh-go"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string1 = /\/tsh_linux_amd64/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string2 = /\/tsh_windows_amd64\.exe/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string3 = /\/tshd\.go/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string4 = /\/tshd_linux_amd64/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string5 = /\/tshd_windows\.go/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string6 = /\/tshd_windows_amd64\.exe/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string7 = /\/tsh\-go\.git/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string8 = /\\tsh_windows_amd64\.exe/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string9 = /\\tshd\.go/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string10 = /\\tshd_windows\.go/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string11 = /\\tshd_windows_amd64\.exe/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string12 = /1647b6e9073cee9751e3cd9a031656a6b830355a7a87d15cdc18601ddfa2f327/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string13 = /32d12ed0ff8db1c95d1ee507561ee0db4c36200277a2bc4cd1b643e385ff5ebe/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string14 = /6c78751a2dd30be8fcb962a93ab912d335a56a7a722dc502bf55eb4c2c7e7c8e/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string15 = /8822c7fa386065eace366042536dcbc277a5be58efae8ce02bf9e4c583e07918/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string16 = /c9bdad45179ca59d8b6b725d329b8ab1ba8e1561c44cc3a14093bfe3c97df3ae/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string17 = /cmd\/tsh\.go/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string18 = /cmd\/tshd\.go/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string19 = /CykuTW\/tsh\-go/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string20 = /tsh_linux_amd64\s/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string21 = /tshd_linux_amd64\s/ nocase ascii wide
        // Description: Tiny SHell Go - An open-source backdoor written in Go
        // Reference: https://github.com/CykuTW/tsh-go
        $string22 = /tshd_windows_amd64\.exe\s/ nocase ascii wide
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
