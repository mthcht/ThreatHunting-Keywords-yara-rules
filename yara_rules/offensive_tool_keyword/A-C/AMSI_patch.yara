rule AMSI_patch
{
    meta:
        description = "Detection patterns for the tool 'AMSI_patch' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AMSI_patch"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Patching AmsiOpenSession by forcing an error branching
        // Reference: https://github.com/TheD1rkMtr/AMSI_patch
        $string1 = /.{0,1000}\/AMSI_patch\.git.{0,1000}/ nocase ascii wide
        // Description: Patching AmsiOpenSession by forcing an error branching
        // Reference: https://github.com/TheD1rkMtr/AMSI_patch
        $string2 = /.{0,1000}\/AmsiOpenSession\.exe.{0,1000}/ nocase ascii wide
        // Description: Patching AmsiOpenSession by forcing an error branching
        // Reference: https://github.com/TheD1rkMtr/AMSI_patch
        $string3 = /.{0,1000}AMS1\-Patch\.exe.{0,1000}/ nocase ascii wide
        // Description: Patching AmsiOpenSession by forcing an error branching
        // Reference: https://github.com/TheD1rkMtr/AMSI_patch
        $string4 = /.{0,1000}AMSI_patch\-main.{0,1000}/ nocase ascii wide
        // Description: Patching AmsiOpenSession by forcing an error branching
        // Reference: https://github.com/TheD1rkMtr/AMSI_patch
        $string5 = /.{0,1000}AmsiOpenSession\.cpp.{0,1000}/ nocase ascii wide
        // Description: Patching AmsiOpenSession by forcing an error branching
        // Reference: https://github.com/TheD1rkMtr/AMSI_patch
        $string6 = /.{0,1000}AmsiOpenSession\.sln.{0,1000}/ nocase ascii wide
        // Description: Patching AmsiOpenSession by forcing an error branching
        // Reference: https://github.com/TheD1rkMtr/AMSI_patch
        $string7 = /.{0,1000}AmsiOpenSession\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Patching AmsiOpenSession by forcing an error branching
        // Reference: https://github.com/TheD1rkMtr/AMSI_patch
        $string8 = /.{0,1000}E09F4899\-D8B3\-4282\-9E3A\-B20EE9A3D463.{0,1000}/ nocase ascii wide
        // Description: Patching AmsiOpenSession by forcing an error branching
        // Reference: https://github.com/TheD1rkMtr/AMSI_patch
        $string9 = /.{0,1000}TheD1rkMtr\/AMSI_patch.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
