rule StealDhcpSecrets
{
    meta:
        description = "Detection patterns for the tool 'StealDhcpSecrets' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "StealDhcpSecrets"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DHCP Server DNS Password Stealer
        // Reference: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/DHCP
        $string1 = /Can\'t\sfind\sDHCP\sServer\sPID\.\sExiting\./ nocase ascii wide
        // Description: DHCP Server DNS Password Stealer
        // Reference: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/DHCP
        $string2 = /define\sDHCP_KEY\s_T\(\"SYSTEM\\\\CurrentControlSet\\\\Services\\\\DHCPServer\\\\ServicePrivateData\"/ nocase ascii wide
        // Description: DHCP Server DNS Password Stealer
        // Reference: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/DHCP
        $string3 = /Impersonation\s\#1\sdone\./ nocase ascii wide
        // Description: DHCP Server DNS Password Stealer
        // Reference: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/DHCP
        $string4 = /Impersonation\s\#1\sfailed\.\sExiting/ nocase ascii wide
        // Description: DHCP Server DNS Password Stealer
        // Reference: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/DHCP
        $string5 = /Impersonation\s\#2\sdone\./ nocase ascii wide
        // Description: DHCP Server DNS Password Stealer
        // Reference: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/DHCP
        $string6 = /Impersonation\s\#2\sfailed\.\sExiting/ nocase ascii wide
        // Description: DHCP Server DNS Password Stealer
        // Reference: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/DHCP
        $string7 = /StealDhcpSecrets\.c/ nocase ascii wide
        // Description: DHCP Server DNS Password Stealer
        // Reference: https://github.com/gtworek/PSBits/tree/master/PasswordStealing/DHCP
        $string8 = /StealDhcpSecrets\.exe/ nocase ascii wide

    condition:
        any of them
}
