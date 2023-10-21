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
        $string2 = /fee\s.*\/.*\s\-l\spl\s\|\sperl/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string3 = /fee\s.*\/.*\s\-l\spl\s\|\sruby/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string4 = /fee\s\-a\s.*killall\ssshd.*\s.*busybox/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string5 = /fee\s\-c\s.*\/.*\s\|\sssh\s.*\@/ nocase ascii wide
        // Description: Execute ELF files without dropping them on disk
        // Reference: https://github.com/nnsee/fileless-elf-exec
        $string6 = /fee\s\-c\s.*\/.*\s\-w\s64\s\|\s/ nocase ascii wide
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

    condition:
        any of them
}