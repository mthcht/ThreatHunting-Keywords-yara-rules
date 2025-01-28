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
        $string1 = /\.\/fee\.py/
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string2 = /fee\s.{0,1000}\/.{0,1000}\s\-l\spl\s\|\sperl/
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string3 = /fee\s.{0,1000}\/.{0,1000}\s\-l\spl\s\|\sruby/
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string4 = /fee\s\-a\s.{0,1000}killall\ssshd.{0,1000}\s.{0,1000}busybox/
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string5 = /fee\s\-c\s.{0,1000}\/.{0,1000}\s\|\sssh\s.{0,1000}\@/
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string6 = /fee\s\-c\s.{0,1000}\/.{0,1000}\s\-w\s64\s\|\s/
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string7 = "fileless-elf-exec" nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string8 = "pip install --user fee"
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string9 = "pipx install fee"
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string10 = /python3\sfee\.py/

    condition:
        any of them
}
