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
        $string1 = /.{0,1000}\\InactiveDomainAdmins\.csv.{0,1000}/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string2 = /.{0,1000}7H0LmBxFtXBPd0\/3vHe7Z3dmdrPZmTzp3ZldQrJ5LOGxeZ.{0,1000}/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string3 = /.{0,1000}7L0LgBxFtTDc093TPe\/dntnM7G6Sncm.{0,1000}/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string4 = /.{0,1000}Fake\sComputer\sObjects\sHoney\sPots.{0,1000}/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string5 = /.{0,1000}Fake\sService\sAccounts\sHoney\sTokens.{0,1000}/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string6 = /.{0,1000}Get\-FakeServiceUsers.{0,1000}/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string7 = /.{0,1000}Get\-InactiveDomainAdmins.{0,1000}/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string8 = /.{0,1000}Inactive\sDomain\sAdmins\sHoney\sTokens.{0,1000}/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string9 = /.{0,1000}InjectedCredentials\.csv.{0,1000}/ nocase ascii wide
        // Description: Microsoft PowerShell module designed for red teams that can be used to find honeypots and honeytokens in the network or at the host
        // Reference: https://github.com/JavelinNetworks/HoneypotBuster
        $string10 = /.{0,1000}Invoke\-HoneypotBuster.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
