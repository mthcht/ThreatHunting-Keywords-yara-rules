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
        $string1 = /\/MSOLSpray/ nocase ascii wide
        // Description: This module will perform password spraying against Microsoft Online accounts (Azure/O365)
        // Reference: https://github.com/dafthack/MSOLSpray
        $string2 = /MSOLSpray\s/ nocase ascii wide
        // Description: This module will perform password spraying against Microsoft Online accounts (Azure/O365)
        // Reference: https://github.com/dafthack/MSOLSpray
        $string3 = /MSOLSpray\.git/ nocase ascii wide
        // Description: This module will perform password spraying against Microsoft Online accounts (Azure/O365)
        // Reference: https://github.com/dafthack/MSOLSpray
        $string4 = /MSOLSpray\.ps1/ nocase ascii wide
        // Description: This module will perform password spraying against Microsoft Online accounts (Azure/O365)
        // Reference: https://github.com/dafthack/MSOLSpray
        $string5 = /MSOLSpray\-master/ nocase ascii wide

    condition:
        any of them
}
