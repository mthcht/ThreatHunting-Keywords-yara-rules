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
        $string1 = /.{0,1000}\/PXEThief.{0,1000}/ nocase ascii wide
        // Description: PXEThief is a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager
        // Reference: https://github.com/MWR-CyberSec/PXEThief
        $string2 = /.{0,1000}auto_exploit_blank_password.{0,1000}/ nocase ascii wide
        // Description: PXEThief is a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager
        // Reference: https://github.com/MWR-CyberSec/PXEThief
        $string3 = /.{0,1000}media_variable_file_cryptography\.py.{0,1000}/ nocase ascii wide
        // Description: PXEThief is a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager
        // Reference: https://github.com/MWR-CyberSec/PXEThief
        $string4 = /.{0,1000}pxethief\s.{0,1000}/ nocase ascii wide
        // Description: PXEThief is a set of tooling that can extract passwords from the Operating System Deployment functionality in Microsoft Endpoint Configuration Manager
        // Reference: https://github.com/MWR-CyberSec/PXEThief
        $string5 = /.{0,1000}pxethief\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
