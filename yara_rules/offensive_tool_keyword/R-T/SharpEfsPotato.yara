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
        $string2 = " SharpEfsPotato" nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string3 = "/SharpEfsPotato" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string4 = /\[\+\]\sServer\sconnected\sto\sour\sevil\sRPC\spipe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string5 = /\[\+\]\sTriggering\sname\spipe\saccess\son\sevil\sPIPE/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string6 = /\\SharpEfsPotato/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string7 = /\\SharpEfsPotato\.pdb/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string8 = ">SharpEfsPotato<" nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string9 = "AAB4D641-C310-4572-A9C2-6D12593AB28E" nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string10 = "SharpEfsPotato by @bugch3ck" nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string11 = "SharpEfsPotato by @bugch3ck" nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string12 = /SharpEfsPotato\.cs/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string13 = /SharpEfsPotato\.exe/ nocase ascii wide
        // Description: executables for penetration testing Windows Active Directory environments
        // Reference: https://github.com/jakobfriedl/precompiled-binaries
        $string14 = /SharpEfsPotato\.exe/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string15 = /SharpEfsPotato\.sln/ nocase ascii wide
        // Description: Local privilege escalation from SeImpersonatePrivilege using EfsRpc.
        // Reference: https://github.com/bugch3ck/SharpEfsPotato
        $string16 = "SharpEfsPotato-master" nocase ascii wide

    condition:
        any of them
}
