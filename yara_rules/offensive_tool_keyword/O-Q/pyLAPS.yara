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
        $string1 = /\spyLAPS\.py/
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string2 = /\/pyLAPS\.git/
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string3 = /\/pyLAPS\.py/
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string4 = "p0dalirius/pyLAPS"
        // Description: A simple way to read and write LAPS passwords from linux.
        // Reference: https://github.com/p0dalirius/pyLAPS
        $string5 = "pyLAPS-main"

    condition:
        any of them
}
