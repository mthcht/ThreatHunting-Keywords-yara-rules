rule fileless_elf_exec
{
    meta:
        description = "Detection patterns for the tool 'fileless-elf-exec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fileless-elf-exec"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string1 = /\.\/fee\.py/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string2 = /fee\s.{0,100}\/.{0,100}\s\-l\spl\s\|\sperl/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string3 = /fee\s.{0,100}\/.{0,100}\s\-l\spl\s\|\sruby/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string4 = /fee\s\-a\s.{0,100}killall\ssshd.{0,100}\s.{0,100}busybox/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string5 = /fee\s\-c\s.{0,100}\/.{0,100}\s\|\sssh\s.{0,100}\@/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string6 = /fee\s\-c\s.{0,100}\/.{0,100}\s\-w\s64\s\|\s/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string7 = /fileless\-elf\-exec/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string8 = /pip\sinstall\s\-\-user\sfee/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string9 = /pipx\sinstall\sfee/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string10 = /python3\sfee\.py/ nocase ascii wide
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
