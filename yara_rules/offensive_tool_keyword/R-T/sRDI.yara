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
        $string1 = /.{0,1000}ConvertTo\-Shellcode\s\-.{0,1000}/ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string2 = /.{0,1000}ConvertTo\-Shellcode\..{0,1000}/ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string3 = /.{0,1000}ConvertToShellcode\.py.{0,1000}/ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string4 = /.{0,1000}Invoke\-Shellcode.{0,1000}/ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string5 = /.{0,1000}monoxgas\/sRDI.{0,1000}/ nocase ascii wide
        // Description: Shellcode Reflective DLL Injection - Shellcode implementation of Reflective DLL Injection. Convert DLLs to position independent shellcode
        // Reference: https://github.com/monoxgas/sRDI
        $string6 = /.{0,1000}ShellcodeRDI\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
