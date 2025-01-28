rule Invoke_RunAsWithCert
{
    meta:
        description = "Detection patterns for the tool 'Invoke-RunAsWithCert' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-RunAsWithCert"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A PowerShell script to perform PKINIT authentication with the Windows API from a non domain-joined machine
        // Reference: https://github.com/synacktiv/Invoke-RunAsWithCert
        $string1 = /\.pfx\s\-Domain\s.{0,1000}\s\-PatchLsass/ nocase ascii wide
        // Description: A PowerShell script to perform PKINIT authentication with the Windows API from a non domain-joined machine
        // Reference: https://github.com/synacktiv/Invoke-RunAsWithCert
        $string2 = /\/Invoke\-RunAsWithCert\.git/ nocase ascii wide
        // Description: A PowerShell script to perform PKINIT authentication with the Windows API from a non domain-joined machine
        // Reference: https://github.com/synacktiv/Invoke-RunAsWithCert
        $string3 = "75dcce94ecc2df9392b92c2be705c72626a22c7c8fad662c8a1f3b4dba0228d8" nocase ascii wide
        // Description: A PowerShell script to perform PKINIT authentication with the Windows API from a non domain-joined machine
        // Reference: https://github.com/synacktiv/Invoke-RunAsWithCert
        $string4 = "Invoke-RunAsWithCert" nocase ascii wide
        // Description: A PowerShell script to perform PKINIT authentication with the Windows API from a non domain-joined machine
        // Reference: https://github.com/synacktiv/Invoke-RunAsWithCert
        $string5 = "synacktiv/Invoke-RunAsWithCert" nocase ascii wide

    condition:
        any of them
}
