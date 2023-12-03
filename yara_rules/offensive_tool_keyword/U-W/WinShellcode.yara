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
        $string1 = /.{0,1000}DallasFR\/WinShellcode.{0,1000}/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string2 = /.{0,1000}shellcode_dll\.dll.{0,1000}/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string3 = /.{0,1000}shellcode_dll\\.{0,1000}/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string4 = /.{0,1000}take_shellcode\.bat.{0,1000}/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string5 = /.{0,1000}text_to_shellcode\\.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string6 = /.{0,1000}WinShellcode\.git.{0,1000}/ nocase ascii wide
        // Description: It's a C code project created in Visual Studio that helps you generate shellcode from your C code.
        // Reference: https://github.com/DallasFR/WinShellcode
        $string7 = /.{0,1000}WinShellcode\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
