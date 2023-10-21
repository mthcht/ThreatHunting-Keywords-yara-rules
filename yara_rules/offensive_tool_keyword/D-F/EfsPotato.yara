rule EfsPotato
{
    meta:
        description = "Detection patterns for the tool 'EfsPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EfsPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string1 = /\/EfsPotato\.git/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string2 = /csc\.exe\sEfsPotato\.cs\s/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string3 = /EfsPotato.*efsrpc/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string4 = /EfsPotato.*lsarpc/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string5 = /EfsPotato.*lsarpc/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string6 = /EfsPotato.*lsass/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string7 = /EfsPotato.*netlogon/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string8 = /EfsPotato.*samr/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string9 = /EfsPotato\-main/ nocase ascii wide

    condition:
        any of them
}