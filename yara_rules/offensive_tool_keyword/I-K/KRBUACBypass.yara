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
        $string2 = /\.exe\sasktgs/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string3 = /\.exe\skrbscm/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string4 = /\/KRBUACBypass/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string5 = /\/KRBUACBypass\.git/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string6 = /\\KRBUACBypass/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string7 = /\\S4U\.Exe/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string8 = /\\SCMUACBypass\.cpp/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string9 = /4291df077f27794311313530ae25457a0fbad23d402c789ed3336ace4b64150c/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string10 = /5d2e0f4adc5e3bb1f154c9f22eee2cf15e0bb2c5815653e3d97cb1e97c99c326/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string11 = /881D4D67\-46DD\-4F40\-A813\-C9D3C8BE0965/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string12 = /ACE_Get\-KerberosTicketCache\.ps1/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string13 = /c3c993b043322cac38d24d751229883227de36b38e2c8c1e0fc1ca0ff6f2fd9a/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string14 = /Copyright\s\(c\)\s2023\swhoamianony\.top/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string15 = /KRBUACBypass\s1/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string16 = /KRBUACBypass\.csproj/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string17 = /KRBUACBypass\.exe/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string18 = /KRBUACBypass\.sln/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string19 = /KRBUACBypass\/tarball/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string20 = /KRBUACBypass\/zipball/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string21 = /lib\/Bruteforcer\.cs/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string22 = /MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string23 = /Rubeus\/1\.0/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string24 = /UACBypassedService/ nocase ascii wide
        // Description: UAC Bypass By Abusing Kerberos Tickets
        // Reference: https://github.com/wh0amitz/KRBUACBypass
        $string25 = /wh0amitz\/KRBUACBypass/ nocase ascii wide

    condition:
        any of them
}
