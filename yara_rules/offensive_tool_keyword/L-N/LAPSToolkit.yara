rule LAPSToolkit
{
    meta:
        description = "Detection patterns for the tool 'LAPSToolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LAPSToolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string1 = /\sLAPSToolkit\.ps1/ nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string2 = /\/LAPSToolkit\.git/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string3 = /\/LAPSToolkit\.ps1/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string4 = /\\LAPSToolkit\.ps1/ nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string5 = "cd05b7676886e560400643e3852e64483cee95f4741ec8a930c7b1f68479835a" nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string6 = "Find-LAPSDelegatedGroups " nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string7 = "LAPSToolkit" nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string8 = /LAPSToolkit\.ps1/ nocase ascii wide
        // Description: Functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsofts Local Administrator Password Solution (LAPS). It includes finding groups specifically delegated by sysadmins. finding users with All Extended Rights that can view passwords. and viewing all computers with LAPS enabled
        // Reference: https://github.com/leoloobeek/LAPSToolkit
        $string9 = "leoloobeek/LAPSToolkit" nocase ascii wide

    condition:
        any of them
}
