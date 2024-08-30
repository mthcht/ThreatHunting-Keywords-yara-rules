rule dcomhijack
{
    meta:
        description = "Detection patterns for the tool 'dcomhijack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dcomhijack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string1 = /\/dcomhijack\.cna/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string2 = /\/dcomhijack\.git/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string3 = /\/dcomhijack\.git/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string4 = /\/dcomhijack\.py/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string5 = /\\dcomhijack\.py/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string6 = /2fe3e062aad09c372500bdef858a32344d95c7b8036d4cb5f0091a2db17b446f/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string7 = /9f1186262760c8424674045530bb64d541acbd5a5364e5e56f23cae01243a59e/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string8 = /dcomhijack\.cna/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string9 = /dcomhijack\.py\s\-object\s/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string10 = /dcomhijack\.py/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string11 = /dcomhijack\-main/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string12 = /upload\-dll\s.{0,1000}\s.{0,1000}\.dll/ nocase ascii wide
        // Description: Lateral Movement Using DCOM with impacket and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string13 = /WKL\-Sec\/dcomhijack/ nocase ascii wide
        // Description: Lateral Movement Using DCOM and DLL Hijacking
        // Reference: https://github.com/WKL-Sec/dcomhijack
        $string14 = /WKL\-Sec\/dcomhijack/ nocase ascii wide

    condition:
        any of them
}
