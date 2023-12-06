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
        $string1 = /\/TakeMyRDP/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string2 = /\\TakeMyRDP/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string3 = /3C601672\-7389\-42B2\-B5C9\-059846E1DA88/ nocase ascii wide
        // Description: An updated version of keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/nocerainfosec/TakeMyRDP2.0
        $string4 = /TakeMyRDP.{0,1000}logfile\.txt/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string5 = /TakeMyRDP\.cpp/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string6 = /TakeMyRDP\.exe/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string7 = /TakeMyRDP\.git/ nocase ascii wide
        // Description: An updated version of keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/nocerainfosec/TakeMyRDP2.0
        $string8 = /TakeMyRDP\.h/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string9 = /TakeMyRDP\.sln/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string10 = /TakeMyRDP\.vcxproj/ nocase ascii wide
        // Description: An updated version of keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/nocerainfosec/TakeMyRDP2.0
        $string11 = /TakeMyRDP2\.0/ nocase ascii wide
        // Description: A keystroke logger targeting the Remote Desktop Protocol (RDP) related processes
        // Reference: https://github.com/TheD1rkMtr/TakeMyRDP
        $string12 = /TakeMyRDP\-main/ nocase ascii wide

    condition:
        any of them
}
