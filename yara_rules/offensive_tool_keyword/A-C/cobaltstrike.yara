rule Cobaltstrike
{
    meta:
        description = "Detection patterns for the tool 'Cobaltstrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Cobaltstrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string1 = /\/PoolPartyBof\.c/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string2 = /\/PoolPartyBof\.git/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string3 = /\/PoolPartyBof\.x64\.o/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string4 = /0xEr3bus\/PoolPartyBof/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string5 = /Allocated\sshellcode\smemory\sin\sthe\starget\sprocess\:\s/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string6 = /PoolParty\sattack\scompleted\ssuccessfully/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string7 = /PoolPartyBof\s/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string8 = /PoolPartyBof\s.{0,1000}\sHTTPSLocal/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string9 = /PoolPartyBof\.cna/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string10 = /PoolPartyBof\-main/ nocase ascii wide
        // Description: A set of fully-undetectable process injection techniques abusing Windows Thread Pools
        // Reference: https://github.com/0xEr3bus/PoolPartyBof
        $string11 = /Starting\sPoolParty\sattack\sagainst\sprocess\sid\:/ nocase ascii wide

    condition:
        any of them
}
