rule DSInternals
{
    meta:
        description = "Detection patterns for the tool 'DSInternals' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DSInternals"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string1 = /Get\-ADDBAccount\s\-All\s\-DBPath\s.{0,1000}\.ntds\.dit.{0,1000}\s\-BootKey/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string2 = /Get\-ADReplAccount\s\-All\s/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string3 = /Install\-Module\s\-Name\sDSInternals/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string4 = /Get\-ADDBAccount.{0,1000}\s\-BootKey.{0,1000}\s\-DBPath\s.{0,1000}\.ntds\.dit/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string5 = /Get\-ADDBAccount.{0,1000}\s\-BootKey.{0,1000}\s\-DataBasePath\s.{0,1000}\.ntds\.dit/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string6 = /Get\-ADDBAccount.{0,1000}\s\-DataBasePath\s.{0,1000}\.ntds\.dit.{0,1000}\s\-BootKey/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string7 = /Set\-SamAccountPasswordHash\s.{0,1000}\s\-NTHash\s/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string8 = /\sGet\-ADReplAccount\s\-SamAccountName\s\'AZUREADSSOACC\$\'\s/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string9 = /\\DSInternals\.psd1/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string10 = /\sDSInternals\.psd1/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string11 = /\/DSInternals\.psd1/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string12 = /Get\-ADDBAccount\s.{0,1000}\s\-DataBasePath\s.{0,1000}ntds\.dit/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string13 = /Get\-ADDBAccount\s.{0,1000}\s\-DBPath\s.{0,1000}ntds\.dit/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string14 = /Test\-PasswordQuality\s\-WeakPasswordHashesSortedFile\s/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string15 = /Import\-Module\sDSInternals/ nocase ascii wide
        // Description: Directory Services Internals (DSInternals) PowerShell Module and Framework - abused by attackers
        // Reference: https://github.com/MichaelGrafnetter/DSInternals
        $string16 = /DSInternals_v4\..{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}
