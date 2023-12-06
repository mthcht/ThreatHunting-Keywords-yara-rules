rule HoneypotBuster
{
    meta:
        description = "Detection patterns for the tool 'HoneypotBuster' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "HoneypotBuster"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string1 = /\\InactiveDomainAdmins\.csv/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string2 = /7H0LmBxFtXBPd0\/3vHe7Z3dmdrPZmTzp3ZldQrJ5LOGxeZ/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string3 = /7L0LgBxFtTDc093TPe\/dntnM7G6Sncm/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string4 = /Fake\sComputer\sObjects\sHoney\sPots/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string5 = /Fake\sService\sAccounts\sHoney\sTokens/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string6 = /Get\-FakeServiceUsers/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string7 = /Get\-InactiveDomainAdmins/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string8 = /Inactive\sDomain\sAdmins\sHoney\sTokens/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string9 = /InjectedCredentials\.csv/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string10 = /Invoke\-HoneypotBuster/ nocase ascii wide

    condition:
        any of them
}
