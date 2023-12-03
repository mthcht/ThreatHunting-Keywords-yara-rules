rule kerberoast
{
    meta:
        description = "Detection patterns for the tool 'kerberoast' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "kerberoast"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string1 = /.{0,1000}\.local\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string2 = /.{0,1000}\/nidem\/kerberoast.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string3 = /.{0,1000}\/xan7r\/kerberoast.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string4 = /.{0,1000}autokerberoast\.ps1.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string5 = /.{0,1000}autokerberoast_noMimikatz\.ps1/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string6 = /.{0,1000}autoKirbi2hashcat\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string7 = /.{0,1000}autoTGS_NtlmCrack\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string8 = /.{0,1000}extracttgsrepfrompcap\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string9 = /.{0,1000}GetUserSPNs\.vbs.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string10 = /.{0,1000}Invoke\-AutoKerberoast.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string11 = /.{0,1000}kerberoast\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string12 = /.{0,1000}kerberos::ptt\s.{0,1000}\.kirbi.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string13 = /.{0,1000}kirbi2john\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string14 = /.{0,1000}krbroast\-pcap2hashcat\.py.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string15 = /.{0,1000}setspn\s\-A\sHTTP\/.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string16 = /.{0,1000}setspn\s\-T\smedin\s\-Q\s.{0,1000}\/.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string17 = /.{0,1000}setspn\.exe\s\-T\smedin\s\-Q\s.{0,1000}\/.{0,1000}/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string18 = /.{0,1000}tgsrepcrack\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
