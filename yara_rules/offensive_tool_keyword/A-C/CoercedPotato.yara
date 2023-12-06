rule CoercedPotato
{
    meta:
        description = "Detection patterns for the tool 'CoercedPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CoercedPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string1 = /\/CoercedPotato\.git/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string2 = /\[\+\]\sRUNNING\sALL\sKNOWN\sEXPLOITS/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string3 = /\\\\\\\\\.\\\\pipe\\\\coerced\\\\pipe\\\\spoolss/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string4 = /\\\\\\\\\.\\\\pipe\\\\coerced\\\\pipe\\\\srvsvc/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string5 = /127\.0\.0\.1\/pipe\/coerced\\\\C\$/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string6 = /337ED7BE\-969A\-40C4\-A356\-BE99561F4633/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string7 = /CoercedPotato\.cpp/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string8 = /CoercedPotato\.exe/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string9 = /CoercedPotato\.sln/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string10 = /CoercedPotato\-master/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string11 = /Prepouce\/CoercedPotato/ nocase ascii wide

    condition:
        any of them
}
