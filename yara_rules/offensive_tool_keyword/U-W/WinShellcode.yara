rule WinShellcode
{
    meta:
        description = "Detection patterns for the tool 'WinShellcode' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WinShellcode"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string1 = /DallasFR\/WinShellcode/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string2 = /shellcode_dll\.dll/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string3 = /shellcode_dll\\/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string4 = /take_shellcode\.bat/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string5 = /text_to_shellcode\\.{0,1000}\.exe/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string6 = /WinShellcode\.git/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string7 = /WinShellcode\-main/ nocase ascii wide

    condition:
        any of them
}
