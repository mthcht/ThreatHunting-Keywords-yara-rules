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
        $string1 = /.{0,1000}\/DCOMPotato\.git.{0,1000}/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string2 = /.{0,1000}854A20FB\-2D44\-457D\-992F\-EF13785D2B51.{0,1000}/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string3 = /.{0,1000}DCOMPotato\..{0,1000}/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string4 = /.{0,1000}DCOMPotato\-master.{0,1000}/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string5 = /.{0,1000}McpManagementPotato\..{0,1000}/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string6 = /.{0,1000}PrinterNotifyPotato\s.{0,1000}/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string7 = /.{0,1000}PrinterNotifyPotato\..{0,1000}/ nocase ascii wide
        // Description: Service DCOM Object and SeImpersonatePrivilege abuse.
        // Reference: https://github.com/zcgonvh/DCOMPotato
        $string8 = /.{0,1000}zcgonvh\/DCOMPotato.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
