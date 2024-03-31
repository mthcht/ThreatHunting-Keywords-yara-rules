rule MutationGate
{
    meta:
        description = "Detection patterns for the tool 'MutationGate' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MutationGate"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // Reference: https://github.com/senzee1984/MutationGate
        $string1 = /\sMutationGate\.cpp/ nocase ascii wide
        // Description: MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // Reference: https://github.com/senzee1984/MutationGate
        $string2 = /\/MutationGate\.git/ nocase ascii wide
        // Description: MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // Reference: https://github.com/senzee1984/MutationGate
        $string3 = /\\MutationGate\.cpp/ nocase ascii wide
        // Description: MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // Reference: https://github.com/senzee1984/MutationGate
        $string4 = /\\MutationGate\.exe/ nocase ascii wide
        // Description: MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // Reference: https://github.com/senzee1984/MutationGate
        $string5 = /\\MutationGate\.sln/ nocase ascii wide
        // Description: MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // Reference: https://github.com/senzee1984/MutationGate
        $string6 = /\\MutationGate\.vcxproj/ nocase ascii wide
        // Description: MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // Reference: https://github.com/senzee1984/MutationGate
        $string7 = /5A0FBE0D\-BACC\-4B97\-8578\-B5B27567EEA7/ nocase ascii wide
        // Description: MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // Reference: https://github.com/senzee1984/MutationGate
        $string8 = /dd3cd4783ec400f215c4f72f797fe310be12453c20944feec054a449835feb36/ nocase ascii wide
        // Description: MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.
        // Reference: https://github.com/senzee1984/MutationGate
        $string9 = /senzee1984\/MutationGate/ nocase ascii wide

    condition:
        any of them
}
