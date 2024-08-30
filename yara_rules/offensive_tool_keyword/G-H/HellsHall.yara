rule HellsHall
{
    meta:
        description = "Detection patterns for the tool 'HellsHall' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HellsHall"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string1 = /\/HellHall\.git/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string2 = /\/HellsHall\.exe/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string3 = /\[\#\]\s\[HELL\sHALL\]\sPress\s\<Enter\>\sTo\sQUIT\s\.\.\.\s/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string4 = /\[\+\]\s\[HELL\sHALL\]\spAddress\s\:\s/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string5 = /\[i\]\s\[HELL\sHALL\]\sPress\s\<Enter\>\sTo\sRun\s\.\.\.\s/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string6 = /\\AsmHell\.asm/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string7 = /\\HellsHall\.c/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string8 = /\\HellsHall\.exe/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string9 = /\\HellsHall\.h/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string10 = /F06EAC7B\-6996\-4E78\-B045\-0DF6ED201367/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string11 = /HellHall\-main\.zip/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string12 = /Hell\'sHall\.vcxproj/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string13 = /Hell\'sHall\-Clang\&NoCrt\.zip/ nocase ascii wide
        // Description: Performing Indirect Clean Syscalls
        // Reference: https://github.com/Maldev-Academy/HellHall
        $string14 = /Maldev\-Academy\/HellHall/ nocase ascii wide

    condition:
        any of them
}
