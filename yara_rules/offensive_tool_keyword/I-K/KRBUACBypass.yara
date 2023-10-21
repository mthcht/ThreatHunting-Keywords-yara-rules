rule KRBUACBypass
{
    meta:
        description = "Detection patterns for the tool 'KRBUACBypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KRBUACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string1 = /\sKRBUACBypass/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string2 = /\/KRBUACBypass/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string3 = /\\KRBUACBypass/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string4 = /881D4D67\-46DD\-4F40\-A813\-C9D3C8BE0965/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string5 = /Copyright\s\(c\)\s2023\swhoamianony\.top/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string6 = /KRBUACBypass\s1/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string7 = /KRBUACBypass\.csproj/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string8 = /KRBUACBypass\.exe/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string9 = /KRBUACBypass\.sln/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string10 = /lib\/Bruteforcer\.cs/ nocase ascii wide

    condition:
        any of them
}