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
        $string1 = /.{0,1000}\.\/fee\.py.{0,1000}/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string2 = /.{0,1000}fee\s.{0,1000}\/.{0,1000}\s\-l\spl\s\|\sperl.{0,1000}/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string3 = /.{0,1000}fee\s.{0,1000}\/.{0,1000}\s\-l\spl\s\|\sruby.{0,1000}/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string4 = /.{0,1000}fee\s\-a\s.{0,1000}killall\ssshd.{0,1000}\s.{0,1000}busybox.{0,1000}/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string5 = /.{0,1000}fee\s\-c\s.{0,1000}\/.{0,1000}\s\|\sssh\s.{0,1000}\@.{0,1000}/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string6 = /.{0,1000}fee\s\-c\s.{0,1000}\/.{0,1000}\s\-w\s64\s\|\s.{0,1000}/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string7 = /.{0,1000}fileless\-elf\-exec.{0,1000}/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string8 = /.{0,1000}pip\sinstall\s\-\-user\sfee/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string9 = /.{0,1000}pipx\sinstall\sfee/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string10 = /.{0,1000}python3\sfee\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
