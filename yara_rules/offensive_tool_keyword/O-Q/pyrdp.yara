rule pyrdp
{
    meta:
        description = "Detection patterns for the tool 'pyrdp' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyrdp"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string1 = /\s\-\-nla\-redirection\-host\s.{0,1000}\s\-\-nla\-redirection\-port\s/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string2 = /\/pyrdp\.git/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string3 = /\/pyrdp\:latest/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string4 = /gosecure\/pyrdp/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string5 = /pyrdp_output\s\-/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string6 = /pyrdp\-clonecert\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string7 = /pyrdp\-convert\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string8 = /pyrdp\-mitm\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string9 = /pyrdp\-player\.py/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string10 = /test_mitm_initialization\.py/ nocase ascii wide

    condition:
        any of them
}
