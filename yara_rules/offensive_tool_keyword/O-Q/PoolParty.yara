rule PoolParty
{
    meta:
        description = "Detection patterns for the tool 'PoolParty' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PoolParty"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string1 = /\sPoolParty\.cpp/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string2 = /\sPoolParty\.exe/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string3 = /\/HandleHijacker\.cpp/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string4 = /\/HandleHijacker\.hpp/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string5 = /\/PoolParty\.cpp/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string6 = /\/PoolParty\.exe/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string7 = /\/PoolParty\.git/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string8 = /\/PoolParty\.hpp/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string9 = /\/PoolParty\.sln/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string10 = /\/PoolParty\.vcxproj/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string11 = /\\HandleHijacker\.cpp/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string12 = /\\HandleHijacker\.hpp/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string13 = /\\PoolParty\.cpp/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string14 = /\\PoolParty\.exe/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string15 = /\\PoolParty\.hpp/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string16 = /\\PoolParty\.sln/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string17 = /\\PoolParty\.vcxproj/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string18 = /\\PoolParty\-PoolParty\\/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string19 = /\\x24\\xC3\\C\:\\\\Windows\\\\System32\\\\calc\.exe\\x00/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string20 = /45D59D79\-EF51\-4A93\-AAFA\-2879FFC3A62C/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string21 = /Allocated\sshellcode\smemory\sin\sthe\starget\sprocess\:\s/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string22 = /Hijacked\stimer\squeue\shandle\sfrom\sthe\starget\sprocess\:\s/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string23 = /Hijacked\sworker\sfactory\shandle\sfrom\sthe\starget\sprocess\:\s/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string24 = /PoolParty\sattack\scompleted\ssuccessfully/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string25 = /PoolParty\.exe\s/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string26 = /PoolParty\-main\.zip/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string27 = /PoolParty\-PoolParty\.zip/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string28 = /SafeBreach\-Labs\/PoolParty/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/SafeBreach-Labs/PoolParty
        $string29 = /Starting\sPoolParty\sattack\sagainst\sprocess\sid\:\s/ nocase ascii wide

    condition:
        any of them
}
