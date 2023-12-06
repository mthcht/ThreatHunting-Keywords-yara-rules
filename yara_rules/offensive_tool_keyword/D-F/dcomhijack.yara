rule dcomhijack
{
    meta:
        description = "Detection patterns for the tool 'dcomhijack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dcomhijack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string1 = /\/dcomhijack\.git/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string2 = /dcomhijack\.cna/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string3 = /dcomhijack\.py/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string4 = /dcomhijack\-main/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string5 = /upload\-dll\s.{0,1000}\s.{0,1000}\.dll/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string6 = /WKL\-Sec\/dcomhijack/ nocase ascii wide

    condition:
        any of them
}
