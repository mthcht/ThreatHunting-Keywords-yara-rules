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
        $string1 = /.{0,1000}.{0,1000}\\Users\\Public\\termsrv\.patch\.dll.{0,1000}/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string2 = /.{0,1000}\/SharpDoor\.cs.{0,1000}/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string3 = /.{0,1000}\/SharpDoor\.git.{0,1000}/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string4 = /.{0,1000}\\SharpDoor\.cs.{0,1000}/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string5 = /.{0,1000}\\Users\\Public\\termsrv\.dll.{0,1000}/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string6 = /.{0,1000}4cec28b4c00002245dffc8346be0cc11.{0,1000}/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string7 = /.{0,1000}infosecn1nja\/SharpDoor.{0,1000}/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string8 = /.{0,1000}SharpDoor\.exe.{0,1000}/ nocase ascii wide
        // Description: SharpDoor is alternative RDPWrap written in C# to allowed multiple RDP (Remote Desktop) sessions by patching termsrv.dll file.
        // Reference: https://github.com/infosecn1nja/SharpDoor
        $string9 = /.{0,1000}SharpDoor\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
