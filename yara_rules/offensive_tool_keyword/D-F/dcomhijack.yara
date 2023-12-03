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
        $string1 = /.{0,1000}\/dcomhijack\.git.{0,1000}/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string2 = /.{0,1000}dcomhijack\.cna.{0,1000}/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string3 = /.{0,1000}dcomhijack\.py.{0,1000}/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string4 = /.{0,1000}dcomhijack\-main.{0,1000}/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string5 = /.{0,1000}upload\-dll\s.{0,1000}\s.{0,1000}\.dll.{0,1000}/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string6 = /.{0,1000}WKL\-Sec\/dcomhijack.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
