rule TakeMyRDP
{
    meta:
        description = "Detection patterns for the tool 'TakeMyRDP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TakeMyRDP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string1 = /.{0,1000}\/TakeMyRDP.{0,1000}/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string2 = /.{0,1000}\\TakeMyRDP.{0,1000}/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string3 = /.{0,1000}3C601672\-7389\-42B2\-B5C9\-059846E1DA88.{0,1000}/ nocase ascii wide
        // Description: An updated version of keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/nocerainfosec/TakeMyRDP2.0
        $string4 = /.{0,1000}TakeMyRDP.{0,1000}logfile\.txt.{0,1000}/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string5 = /.{0,1000}TakeMyRDP\.cpp.{0,1000}/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string6 = /.{0,1000}TakeMyRDP\.exe.{0,1000}/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string7 = /.{0,1000}TakeMyRDP\.git.{0,1000}/ nocase ascii wide
        // Description: An updated version of keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/nocerainfosec/TakeMyRDP2.0
        $string8 = /.{0,1000}TakeMyRDP\.h.{0,1000}/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string9 = /.{0,1000}TakeMyRDP\.sln.{0,1000}/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string10 = /.{0,1000}TakeMyRDP\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: An updated version of keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/nocerainfosec/TakeMyRDP2.0
        $string11 = /.{0,1000}TakeMyRDP2\.0.{0,1000}/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string12 = /.{0,1000}TakeMyRDP\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
