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
        $string1 = /\.local\.kirbi/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string2 = /\/nidem\/kerberoast/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string3 = /\/xan7r\/kerberoast/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string4 = /autokerberoast\.ps1/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string5 = /autokerberoast_noMimikatz\.ps1/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string6 = /autoKirbi2hashcat\.py/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string7 = /autoTGS_NtlmCrack\.py/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string8 = /extracttgsrepfrompcap\.py/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string9 = /GetUserSPNs\.vbs/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/xan7r/kerberoast
        $string10 = /Invoke\-AutoKerberoast/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string11 = /kerberoast\.py/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string12 = /kerberos::ptt\s.*\.kirbi/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string13 = /kirbi2john\.py/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string14 = /krbroast\-pcap2hashcat\.py/ nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string15 = /setspn\s\-A\sHTTP\// nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string16 = /setspn\s\-T\smedin\s\-Q\s.*\// nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string17 = /setspn\.exe\s\-T\smedin\s\-Q\s.*\// nocase ascii wide
        // Description: Kerberoast is a series of tools for attacking MS Kerberos implementations
        // Reference: https://github.com/nidem/kerberoast
        $string18 = /tgsrepcrack\.py/ nocase ascii wide

    condition:
        any of them
}