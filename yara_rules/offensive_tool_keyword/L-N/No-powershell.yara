rule No_powershell
{
    meta:
        description = "Detection patterns for the tool 'No-powershell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "No-powershell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string1 = /.{0,1000}\sNo\-PowerShell\.cs.{0,1000}/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string2 = /.{0,1000}\/No\-PowerShell\.cs.{0,1000}/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string3 = /.{0,1000}\/No\-PowerShell\.exe.{0,1000}/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string4 = /.{0,1000}\\No\-PowerShell\.cs.{0,1000}/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string5 = /.{0,1000}\\No\-PowerShell\.exe.{0,1000}/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string6 = /.{0,1000}c:\\temp\\something\.ps1.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
