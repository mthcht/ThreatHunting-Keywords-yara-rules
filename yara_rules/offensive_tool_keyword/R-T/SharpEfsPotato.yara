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
        $string1 = /\sC\:\\temp\\w\.log/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string2 = /\sSharpEfsPotato/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string3 = /\/SharpEfsPotato/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string4 = /\\SharpEfsPotato/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string5 = /AAB4D641\-C310\-4572\-A9C2\-6D12593AB28E/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string6 = /SharpEfsPotato\sby\s\@bugch3ck/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string7 = /SharpEfsPotato\.cs/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string8 = /SharpEfsPotato\.exe/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string9 = /SharpEfsPotato\.sln/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string10 = /SharpEfsPotato\-master/ nocase ascii wide

    condition:
        any of them
}
