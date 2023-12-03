rule SharpBlackout
{
    meta:
        description = "Detection patterns for the tool 'SharpBlackout' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpBlackout"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string1 = /.{0,1000}\/SharpBlackout\.git.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string2 = /.{0,1000}07DFC5AA\-5B1F\-4CCC\-A3D3\-816ECCBB6CB6.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string3 = /.{0,1000}dmcxblue\/SharpBlackout.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string4 = /.{0,1000}SharpBlackout.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string5 = /.{0,1000}SharpBlackOut\.csproj.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string6 = /.{0,1000}SharpBlackout\.exe.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string7 = /.{0,1000}SharpBlackOut\.pdb.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string8 = /.{0,1000}SharpBlackOut\.sln.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string9 = /.{0,1000}SharpBlackout\-main.{0,1000}/ nocase ascii wide
        // Description: Terminate AV/EDR leveraging BYOVD attack
        // Reference: https://github.com/dmcxblue/SharpBlackout
        $string10 = /.{0,1000}Terminating\sWindows\sDefender\?.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
