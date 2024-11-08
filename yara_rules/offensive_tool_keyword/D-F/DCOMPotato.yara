rule DCOMPotato
{
    meta:
        description = "Detection patterns for the tool 'DCOMPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DCOMPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string1 = /\/DCOMPotato\.git/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string2 = /DCOMPotato\./ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string3 = /DCOMPotato\-master/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string4 = /McpManagementPotato\./ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string5 = /PrinterNotifyPotato\s/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string6 = /PrinterNotifyPotato\./ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string7 = /zcgonvh\/DCOMPotato/ nocase ascii wide

    condition:
        any of them
}
