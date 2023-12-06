rule sRDI
{
    meta:
        description = "Detection patterns for the tool 'sRDI' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sRDI"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string1 = /ConvertTo\-Shellcode\s\-/ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string2 = /ConvertTo\-Shellcode\./ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string3 = /ConvertToShellcode\.py/ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string4 = /Invoke\-Shellcode/ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string5 = /monoxgas\/sRDI/ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string6 = /ShellcodeRDI\./ nocase ascii wide

    condition:
        any of them
}
