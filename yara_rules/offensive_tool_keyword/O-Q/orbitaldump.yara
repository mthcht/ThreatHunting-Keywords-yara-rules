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
        $string1 = /\/orbitaldump\.git/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string2 = /k4yt3x\/orbitaldump/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string3 = /orbitaldump\.py/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string4 = /orbitaldump\/orbitaldump/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string5 = /python\s\-m\sorbitaldump\s/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string6 = /python3\s\-m\sorbitaldump\s/ nocase ascii wide
        // Description: A simple multi-threaded distributed SSH brute-forcing tool written in Python.
        // Reference: https://github.com/k4yt3x/orbitaldump
        $string7 = /\-\-user\sorbitaldump/ nocase ascii wide

    condition:
        any of them
}
