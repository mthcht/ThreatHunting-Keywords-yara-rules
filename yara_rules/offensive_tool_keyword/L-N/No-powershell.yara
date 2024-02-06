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
        $string1 = /\sNo\-PowerShell\.cs/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string2 = /\/No\-PowerShell\.cs/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string3 = /\/No\-PowerShell\.exe/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string4 = /\\No\-PowerShell\.cs/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string5 = /\\No\-PowerShell\.exe/ nocase ascii wide
        // Description: powershell script to C# (no-powershell)
        // Reference: https://github.com/gtworek/PSBits/blob/master/Misc/No-PowerShell.cs
        $string6 = /c\:\\temp\\something\.ps1/ nocase ascii wide

    condition:
        any of them
}
