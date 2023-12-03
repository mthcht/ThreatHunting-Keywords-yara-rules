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
        $string1 = /.{0,1000}\/EfsPotato\.git.{0,1000}/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string2 = /.{0,1000}csc\.exe\sEfsPotato\.cs\s.{0,1000}/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string3 = /.{0,1000}EfsPotato.{0,1000}efsrpc.{0,1000}/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string4 = /.{0,1000}EfsPotato.{0,1000}lsarpc.{0,1000}/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string5 = /.{0,1000}EfsPotato.{0,1000}lsarpc.{0,1000}/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string6 = /.{0,1000}EfsPotato.{0,1000}lsass.{0,1000}/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string7 = /.{0,1000}EfsPotato.{0,1000}netlogon.{0,1000}/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string8 = /.{0,1000}EfsPotato.{0,1000}samr.{0,1000}/ nocase ascii wide
        // Description: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability)
        // Reference: https://github.com/zcgonvh/EfsPotato
        $string9 = /.{0,1000}EfsPotato\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
