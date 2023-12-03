rule pyLAPS
{
    meta:
        description = "Detection patterns for the tool 'pyLAPS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyLAPS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string1 = /.{0,1000}\spyLAPS\.py.{0,1000}/ nocase ascii wide
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string2 = /.{0,1000}\/pyLAPS\.git.{0,1000}/ nocase ascii wide
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string3 = /.{0,1000}\/pyLAPS\.py.{0,1000}/ nocase ascii wide
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string4 = /.{0,1000}p0dalirius\/pyLAPS.{0,1000}/ nocase ascii wide
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string5 = /.{0,1000}pyLAPS\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
