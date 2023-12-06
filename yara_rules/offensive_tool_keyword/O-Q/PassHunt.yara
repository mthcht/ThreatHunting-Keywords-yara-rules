rule PassHunt
{
    meta:
        description = "Detection patterns for the tool 'PassHunt' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PassHunt"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PassHunt searches drives for documents that contain passwords or any other regular expression. Its designed to be a simple. standalone tool that can be run from a USB stick.
        // Reference: https://github.com/Dionach/PassHunt
        $string1 = /Dionach.{0,1000}PassHunt/ nocase ascii wide
        // Description: PassHunt searches drives for documents that contain passwords or any other regular expression. Its designed to be a simple. standalone tool that can be run from a USB stick.
        // Reference: https://github.com/Dionach/PassHunt
        $string2 = /passhunt\.exe/ nocase ascii wide
        // Description: PassHunt searches drives for documents that contain passwords or any other regular expression. Its designed to be a simple. standalone tool that can be run from a USB stick.
        // Reference: https://github.com/Dionach/PassHunt
        $string3 = /passhunt\.py/ nocase ascii wide

    condition:
        any of them
}
