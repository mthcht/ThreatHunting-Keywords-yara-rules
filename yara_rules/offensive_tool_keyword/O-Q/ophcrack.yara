rule ophcrack
{
    meta:
        description = "Detection patterns for the tool 'ophcrack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ophcrack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows password cracker based on rainbow tables.
        // Reference: https://gitlab.com/objectifsecurite/ophcrack
        $string1 = /ophcrack/ nocase ascii wide

    condition:
        any of them
}
