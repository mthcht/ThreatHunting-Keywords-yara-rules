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
        $string1 = /\sinteract\s\-u\shttp.{0,1000}\:\/\/.{0,1000}\/.{0,1000}\.aspx\s\-p\s/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string2 = /\/SharPyShell/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string3 = /\\SharPyShell/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string4 = /inject_dll_reflective\.py/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string5 = /inject_dll_srdi\.py/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string6 = /inject_shellcode\.py/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string7 = /JuicyPotato\.exe/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string8 = /juicypotato_reflective\.dll/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string9 = /lateral_wmi\.py/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string10 = /messagebox_reflective\.dll/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string11 = /net_portscan\.py/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string12 = /privesc_juicy_potato\.py/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string13 = /privesc_powerup\.py/ nocase ascii wide
        // Description: SharPyShell is a tiny and obfuscated ASP.NET webshell that executes commands received by an encrypted channel compiling them in memory at runtime.
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string14 = /SharPyShell/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string15 = /sharpyshell\.aspx/ nocase ascii wide
        // Description: SharPyShell - tiny and obfuscated ASP.NET webshell for C# web
        // Reference: https://github.com/antonioCoco/SharPyShell
        $string16 = /SharPyShell\.py/ nocase ascii wide

    condition:
        any of them
}
