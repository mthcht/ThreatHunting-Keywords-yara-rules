rule SharpDoor
{
    meta:
        description = "Detection patterns for the tool 'SharpDoor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDoor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string1 = /\sSharpDoor\.cs/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string2 = /\sSharpDoor\.exe/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string3 = /\/SharpDoor\.cs/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string4 = /\/SharpDoor\.exe/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string5 = /\/SharpDoor\.git/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string6 = /\/SharpDoor\.git/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string7 = /\[\!\]\sUnhandled\sSharpDoor\sexception/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string8 = /\\SharpDoor\.cs/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string9 = /\\SharpDoor\.exe/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string10 = /\\termsrv\.patch\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string11 = /\\Users\\Public\\termsrv\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string12 = /\\Users\\Public\\termsrv\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string13 = /\\Users\\Public\\termsrv\.patch\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string14 = /4cec28b4c00002245dffc8346be0cc11/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string15 = /Allow\sMultiple\sRDP\s\(Remote\sDesktop\)\sSessions\sBy\sPatching\stermsrv\.dll\sFile/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string16 = /infosecn1nja\/SharpDoor/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string17 = /infosecn1nja\/SharpDoor/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string18 = /SharpDoor\.exe/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string19 = /SharpDoor\-master/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string20 = /SharpDoor\-master/ nocase ascii wide

    condition:
        any of them
}
