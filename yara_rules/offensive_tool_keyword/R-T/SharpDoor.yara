rule SharpDoor
{
    meta:
        description = "Detection patterns for the tool 'SharpDoor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpDoor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string1 = /.*\\Users\\Public\\termsrv\.patch\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string2 = /\/SharpDoor\.cs/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string3 = /\/SharpDoor\.git/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string4 = /\\SharpDoor\.cs/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string5 = /\\Users\\Public\\termsrv\.dll/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string6 = /4cec28b4c00002245dffc8346be0cc11/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string7 = /infosecn1nja\/SharpDoor/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string8 = /SharpDoor\.exe/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string9 = /SharpDoor\-master/ nocase ascii wide

    condition:
        any of them
}