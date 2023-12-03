rule orbitaldump
{
    meta:
        description = "Detection patterns for the tool 'orbitaldump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "orbitaldump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string1 = /.{0,1000}\/orbitaldump\.git.{0,1000}/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string2 = /.{0,1000}k4yt3x\/orbitaldump.{0,1000}/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string3 = /.{0,1000}orbitaldump\.py.{0,1000}/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string4 = /.{0,1000}orbitaldump\/orbitaldump.{0,1000}/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string5 = /.{0,1000}python\s\-m\sorbitaldump\s.{0,1000}/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string6 = /.{0,1000}python3\s\-m\sorbitaldump\s.{0,1000}/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string7 = /.{0,1000}\-\-user\sorbitaldump.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
