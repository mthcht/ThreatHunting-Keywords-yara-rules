rule MSOLSpray
{
    meta:
        description = "Detection patterns for the tool 'MSOLSpray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MSOLSpray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This module will perform password spraying against Microsoft Online accounts (Azure/O365)
        // Reference: https://github.com/dafthack/MSOLSpray
        $string1 = /.{0,1000}\/MSOLSpray.{0,1000}/ nocase ascii wide
        // Description: This module will perform password spraying against Microsoft Online accounts (Azure/O365)
        // Reference: https://github.com/dafthack/MSOLSpray
        $string2 = /.{0,1000}MSOLSpray\s.{0,1000}/ nocase ascii wide
        // Description: This module will perform password spraying against Microsoft Online accounts (Azure/O365)
        // Reference: https://github.com/dafthack/MSOLSpray
        $string3 = /.{0,1000}MSOLSpray\.git.{0,1000}/ nocase ascii wide
        // Description: This module will perform password spraying against Microsoft Online accounts (Azure/O365)
        // Reference: https://github.com/dafthack/MSOLSpray
        $string4 = /.{0,1000}MSOLSpray\.ps1.{0,1000}/ nocase ascii wide
        // Description: This module will perform password spraying against Microsoft Online accounts (Azure/O365)
        // Reference: https://github.com/dafthack/MSOLSpray
        $string5 = /.{0,1000}MSOLSpray\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
