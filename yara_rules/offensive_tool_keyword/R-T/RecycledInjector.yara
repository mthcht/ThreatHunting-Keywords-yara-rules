rule RecycledInjector
{
    meta:
        description = "Detection patterns for the tool 'RecycledInjector' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RecycledInjector"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string1 = /\/RecycledInjector/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string2 = /\/RecycledInjector\.git/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string3 = /\/src\/RecycledGate\.h/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string4 = /\\RecycledGate\.c/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string5 = /GateTrampolin\.asm/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string6 = /poc\.exe.{0,1000}poc\.txt/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string7 = /RecycledInjector\.exe/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string8 = /RecycledInjector\-main/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string9 = /RecycledInjector\-main/ nocase ascii wide

    condition:
        any of them
}
