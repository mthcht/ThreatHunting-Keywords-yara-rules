rule FMFASweep
{
    meta:
        description = "Detection patterns for the tool 'FMFASweep' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FMFASweep"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for checking if MFA is enabled on multiple Microsoft Services
        // Reference: https://github.com/dafthack/MFASweep
        $string1 = /.{0,1000}\/MFASweep\.git.{0,1000}/ nocase ascii wide
        // Description: A tool for checking if MFA is enabled on multiple Microsoft Services
        // Reference: https://github.com/dafthack/MFASweep
        $string2 = /.{0,1000}dafthack\/MFASweep.{0,1000}/ nocase ascii wide
        // Description: A tool for checking if MFA is enabled on multiple Microsoft Services
        // Reference: https://github.com/dafthack/MFASweep
        $string3 = /.{0,1000}Invoke\-MFASweep.{0,1000}/ nocase ascii wide
        // Description: A tool for checking if MFA is enabled on multiple Microsoft Services
        // Reference: https://github.com/dafthack/MFASweep
        $string4 = /.{0,1000}MFASweep\.ps1.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
