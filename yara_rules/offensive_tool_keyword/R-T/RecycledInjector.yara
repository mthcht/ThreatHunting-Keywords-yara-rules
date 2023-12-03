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
        $string1 = /.{0,1000}\/RecycledInjector.{0,1000}/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string2 = /.{0,1000}\/RecycledInjector\.git.{0,1000}/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string3 = /.{0,1000}\/src\/RecycledGate\.h.{0,1000}/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string4 = /.{0,1000}\\RecycledGate\.c.{0,1000}/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string5 = /.{0,1000}GateTrampolin\.asm.{0,1000}/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string6 = /.{0,1000}poc\.exe.{0,1000}poc\.txt.{0,1000}/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string7 = /.{0,1000}RecycledInjector\.exe.{0,1000}/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string8 = /.{0,1000}RecycledInjector\-main.{0,1000}/ nocase ascii wide
        // Description: Native Syscalls Shellcode Injector
        // Reference: https://github.com/florylsk/RecycledInjector
        $string9 = /.{0,1000}RecycledInjector\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
