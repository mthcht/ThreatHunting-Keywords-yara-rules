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
        $string1 = /.{0,1000}\sKRBUACBypass.{0,1000}/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string2 = /.{0,1000}\/KRBUACBypass.{0,1000}/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string3 = /.{0,1000}\\KRBUACBypass.{0,1000}/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string4 = /.{0,1000}881D4D67\-46DD\-4F40\-A813\-C9D3C8BE0965.{0,1000}/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string5 = /.{0,1000}Copyright\s\(c\)\s2023\swhoamianony\.top.{0,1000}/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string6 = /.{0,1000}KRBUACBypass\s1.{0,1000}/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string7 = /.{0,1000}KRBUACBypass\.csproj.{0,1000}/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string8 = /.{0,1000}KRBUACBypass\.exe.{0,1000}/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string9 = /.{0,1000}KRBUACBypass\.sln.{0,1000}/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string10 = /.{0,1000}lib\/Bruteforcer\.cs.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
