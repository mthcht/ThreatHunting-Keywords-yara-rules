rule SharpEfsPotato
{
    meta:
        description = "Detection patterns for the tool 'SharpEfsPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpEfsPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string1 = /.{0,1000}\sC:\\temp\\w\.log.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string2 = /.{0,1000}\sSharpEfsPotato.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string3 = /.{0,1000}\/SharpEfsPotato.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string4 = /.{0,1000}\\SharpEfsPotato.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string5 = /.{0,1000}AAB4D641\-C310\-4572\-A9C2\-6D12593AB28E.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string6 = /.{0,1000}SharpEfsPotato\sby\s\@bugch3ck.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string7 = /.{0,1000}SharpEfsPotato\.cs.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string8 = /.{0,1000}SharpEfsPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string9 = /.{0,1000}SharpEfsPotato\.sln.{0,1000}/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string10 = /.{0,1000}SharpEfsPotato\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
