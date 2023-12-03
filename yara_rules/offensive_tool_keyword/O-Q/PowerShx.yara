rule PowerShx
{
    meta:
        description = "Detection patterns for the tool 'PowerShx' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerShx"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Run Powershell without software restrictions.
        // Reference: https://github.com/iomoath/PowerShx
        $string1 = /.{0,1000}\/PowerShx\.git.{0,1000}/ nocase ascii wide
        // Description: Run Powershell without software restrictions.
        // Reference: https://github.com/iomoath/PowerShx
        $string2 = /.{0,1000}1E70D62D\-CC36\-480F\-82BB\-E9593A759AF9.{0,1000}/ nocase ascii wide
        // Description: Run Powershell without software restrictions.
        // Reference: https://github.com/iomoath/PowerShx
        $string3 = /.{0,1000}A17656B2\-42D1\-42CD\-B76D\-9B60F637BCB5.{0,1000}/ nocase ascii wide
        // Description: Run Powershell without software restrictions.
        // Reference: https://github.com/iomoath/PowerShx
        $string4 = /.{0,1000}iomoath\/PowerShx.{0,1000}/ nocase ascii wide
        // Description: Run Powershell without software restrictions.
        // Reference: https://github.com/iomoath/PowerShx
        $string5 = /.{0,1000}PowerShx\.dll.{0,1000}/ nocase ascii wide
        // Description: Run Powershell without software restrictions.
        // Reference: https://github.com/iomoath/PowerShx
        $string6 = /.{0,1000}PowerShx\.exe.{0,1000}/ nocase ascii wide
        // Description: Run Powershell without software restrictions.
        // Reference: https://github.com/iomoath/PowerShx
        $string7 = /.{0,1000}PowerShx\.sln.{0,1000}/ nocase ascii wide
        // Description: Run Powershell without software restrictions.
        // Reference: https://github.com/iomoath/PowerShx
        $string8 = /.{0,1000}PowerShxDll\.csproj.{0,1000}/ nocase ascii wide
        // Description: Run Powershell without software restrictions.
        // Reference: https://github.com/iomoath/PowerShx
        $string9 = /.{0,1000}PowerShx\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
