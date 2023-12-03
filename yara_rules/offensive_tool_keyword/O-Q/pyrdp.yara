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
        $string1 = /.{0,1000}\s\-\-nla\-redirection\-host\s.{0,1000}\s\-\-nla\-redirection\-port\s.{0,1000}/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string2 = /.{0,1000}\/pyrdp\.git.{0,1000}/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string3 = /.{0,1000}\/pyrdp:latest.{0,1000}/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string4 = /.{0,1000}gosecure\/pyrdp.{0,1000}/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string5 = /.{0,1000}pyrdp_output\s\-.{0,1000}/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string6 = /.{0,1000}pyrdp\-clonecert\.py.{0,1000}/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string7 = /.{0,1000}pyrdp\-convert\.py.{0,1000}/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string8 = /.{0,1000}pyrdp\-mitm\.py.{0,1000}/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string9 = /.{0,1000}pyrdp\-player\.py.{0,1000}/ nocase ascii wide
        // Description: RDP monster-in-the-middle (mitm) and library for Python with the ability to watch connections live or after the fact
        // Reference: https://github.com/GoSecure/pyrdp
        $string10 = /.{0,1000}test_mitm_initialization\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
