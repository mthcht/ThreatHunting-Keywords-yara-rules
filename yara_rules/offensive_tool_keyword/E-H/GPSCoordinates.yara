rule GPSCoordinates
{
    meta:
        description = "Detection patterns for the tool 'GPSCoordinates' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GPSCoordinates"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Tracks the system's GPS coordinates (accurate within 1km currently) if Location Services are enabled
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/GPSCoordinates
        $string1 = /.{0,1000}\/master\/GPSCoordinates\/.{0,1000}/ nocase ascii wide
        // Description: Tracks the system's GPS coordinates (accurate within 1km currently) if Location Services are enabled
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/GPSCoordinates
        $string2 = /.{0,1000}\\master\\GPSCoordinates\\.{0,1000}/ nocase ascii wide
        // Description: Tracks the system's GPS coordinates (accurate within 1km currently) if Location Services are enabled
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/GPSCoordinates
        $string3 = /.{0,1000}GPSCoordinates\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
