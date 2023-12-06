rule pxethief
{
    meta:
        description = "Detection patterns for the tool 'pxethief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pxethief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PXEThief is a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager
        // Reference: https://github.com/MWR-CyberSec/PXEThief
        $string1 = /\/PXEThief/ nocase ascii wide
        // Description: PXEThief is a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager
        // Reference: https://github.com/MWR-CyberSec/PXEThief
        $string2 = /auto_exploit_blank_password/ nocase ascii wide
        // Description: PXEThief is a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager
        // Reference: https://github.com/MWR-CyberSec/PXEThief
        $string3 = /media_variable_file_cryptography\.py/ nocase ascii wide
        // Description: PXEThief is a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager
        // Reference: https://github.com/MWR-CyberSec/PXEThief
        $string4 = /pxethief\s/ nocase ascii wide
        // Description: PXEThief is a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager
        // Reference: https://github.com/MWR-CyberSec/PXEThief
        $string5 = /pxethief\.py/ nocase ascii wide

    condition:
        any of them
}
