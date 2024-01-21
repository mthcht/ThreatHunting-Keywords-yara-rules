rule MFASweep
{
    meta:
        description = "Detection patterns for the tool 'MFASweep' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MFASweep"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool for checking if MFA is enabled on multiple Microsoft Services
        // Reference: https://github.com/dafthack/MFASweep
        $string1 = /\s\-Username\s.{0,1000}\s\-Password\s.{0,1000}\s\-Recon\s\-IncludeADFS/ nocase ascii wide
        // Description: A tool for checking if MFA is enabled on multiple Microsoft Services
        // Reference: https://github.com/dafthack/MFASweep
        $string2 = /\/MFASweep\.git/ nocase ascii wide
        // Description: A tool for checking if MFA is enabled on multiple Microsoft Services
        // Reference: https://github.com/dafthack/MFASweep
        $string3 = /dafthack\/MFASweep/ nocase ascii wide
        // Description: A tool for checking if MFA is enabled on multiple Microsoft Services
        // Reference: https://github.com/dafthack/MFASweep
        $string4 = /Invoke\-MFASweep/ nocase ascii wide
        // Description: A tool for checking if MFA is enabled on multiple Microsoft Services
        // Reference: https://github.com/dafthack/MFASweep
        $string5 = /MFASweep\.ps1/ nocase ascii wide

    condition:
        any of them
}
