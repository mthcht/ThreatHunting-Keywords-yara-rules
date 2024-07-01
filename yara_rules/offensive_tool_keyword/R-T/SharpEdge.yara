rule SharpEdge
{
    meta:
        description = "Detection patterns for the tool 'SharpEdge' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEdge"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string1 = /\/SharpEdge\.exe/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string2 = /\/SharpEdge\.git/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string3 = /\\SharpEdge\.csproj/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string4 = /\\SharpEdge\.exe/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string5 = /\\SharpEdge\.sln/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string6 = /\\SharpEdge\-master/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string7 = /0d21ae4c38549782f8b066155b671b2a356721209a5ecaa64bba6edcc6e2f97e/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string8 = /2388c7f7f1073b922d235f675e32e1b6b8809dcef1cce1113bf712402cbad1cd/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string9 = /75f068e65a36c0dfcd7b59c00ab3a0e73f6bc07ca84091f472caada25e32cfcd/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string10 = /D116BEC7\-8DEF\-4FCE\-BF84\-C8504EF4E481/ nocase ascii wide
        // Description: C# Implementation of Get-VaultCredential - Displays Windows vault credential objects including cleartext web credentials - based on  https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-VaultCredential.ps1
        // Reference: https://github.com/rvrsh3ll/SharpEdge
        $string11 = /rvrsh3ll\/SharpEdge/ nocase ascii wide

    condition:
        any of them
}
