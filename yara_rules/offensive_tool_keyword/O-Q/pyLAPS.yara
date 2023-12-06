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
        $string1 = /\spyLAPS\.py/ nocase ascii wide
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string2 = /\/pyLAPS\.git/ nocase ascii wide
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string3 = /\/pyLAPS\.py/ nocase ascii wide
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string4 = /p0dalirius\/pyLAPS/ nocase ascii wide
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string5 = /pyLAPS\-main/ nocase ascii wide

    condition:
        any of them
}
