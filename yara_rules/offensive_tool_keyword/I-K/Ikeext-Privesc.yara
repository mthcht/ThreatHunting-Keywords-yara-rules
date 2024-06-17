rule Ikeext_Privesc
{
    meta:
        description = "Detection patterns for the tool 'Ikeext-Privesc' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Ikeext-Privesc"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string1 = /\/Ikeext\-Privesc\.git/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string2 = /\\Ikeext\-Privesc/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string3 = /57c1670e15a47e02637545cc4a3ad421000a98279df961fc6d454a5c0271421e/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string4 = /DllInjection\.dll/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string5 = /IKEEXT\sDLL\sHijacking/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string6 = /Ikeext\-Privesc\.ps1/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string7 = /Invoke\-IkeextCheck/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string8 = /Invoke\-IkeextExploit/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string9 = /net\sstop\sIKEEXT/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string10 = /securycore\/Ikeext\-Privesc/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string11 = /The\sexploit\sis\sready\.\sA\sreboot\sis\snow\srequired\sto\strigger\sit/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string12 = /TVqQAAMAAAAEAAAA\/\/8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\+AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAADn8UE/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string13 = /W0lLRUVYVF0NCk1FRElBPXJhc3RhcGkNClBvcnQ9VlBOMi0wDQpEZXZpY2U9V2FuIE1pbmlwb3J0IChJS0V2MikNCkRFVklDRT12cG4NClBob25lTnVtYmVyPTEyNy4wLjAuMQ\=\=/ nocase ascii wide
        // Description: Windows IKEEXT DLL Hijacking Exploit Tool
        // Reference: https://github.com/securycore/Ikeext-Privesc
        $string14 = /wlbsctrl_payload\.bat/ nocase ascii wide

    condition:
        any of them
}
