rule SharPyShell
{
    meta:
        description = "Detection patterns for the tool 'SharPyShell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharPyShell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string1 = /.{0,1000}\sinteract\s\-u\shttp.{0,1000}:\/\/.{0,1000}\/.{0,1000}\.aspx\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string2 = /.{0,1000}\/SharPyShell.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string3 = /.{0,1000}\\SharPyShell.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string4 = /.{0,1000}inject_dll_reflective\.py.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string5 = /.{0,1000}inject_dll_srdi\.py.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string6 = /.{0,1000}inject_shellcode\.py.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string7 = /.{0,1000}JuicyPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string8 = /.{0,1000}juicypotato_reflective\.dll.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string9 = /.{0,1000}lateral_wmi\.py.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string10 = /.{0,1000}messagebox_reflective\.dll.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string11 = /.{0,1000}net_portscan\.py.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string12 = /.{0,1000}privesc_juicy_potato\.py.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string13 = /.{0,1000}privesc_powerup\.py.{0,1000}/ nocase ascii wide
        // Description: SharPyShell is a tiny and obfuscated ASP.NET webshell that executes commands received by an encrypted channel compiling them in memory at runtime.
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string14 = /.{0,1000}SharPyShell.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string15 = /.{0,1000}sharpyshell\.aspx.{0,1000}/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string16 = /.{0,1000}SharPyShell\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
