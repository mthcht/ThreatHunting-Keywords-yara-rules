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
        $string1 = /.{0,1000}\/CoercedPotato\.git.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string2 = /.{0,1000}\[\+\]\sRUNNING\sALL\sKNOWN\sEXPLOITS.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string3 = /.{0,1000}\\\\\\\\\.\\\\pipe\\\\coerced\\\\pipe\\\\spoolss.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string4 = /.{0,1000}\\\\\\\\\.\\\\pipe\\\\coerced\\\\pipe\\\\srvsvc.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string5 = /.{0,1000}127\.0\.0\.1\/pipe\/coerced\\\\C\$.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string6 = /.{0,1000}337ED7BE\-969A\-40C4\-A356\-BE99561F4633.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string7 = /.{0,1000}CoercedPotato\.cpp.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string8 = /.{0,1000}CoercedPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string9 = /.{0,1000}CoercedPotato\.sln.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string10 = /.{0,1000}CoercedPotato\-master.{0,1000}/ nocase ascii wide
        // Description: CoercedPotato From Patate (LOCAL/NETWORK SERVICE) to SYSTEM by abusing SeImpersonatePrivilege on Windows 10 Windows 11 and Server 2022.
        // Reference: https://github.com/Prepouce/CoercedPotato
        $string11 = /.{0,1000}Prepouce\/CoercedPotato.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
