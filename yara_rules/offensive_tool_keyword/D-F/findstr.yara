rule findstr
{
    meta:
        description = "Detection patterns for the tool 'findstr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "findstr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: findstr used to find credentials
        // Reference: N/A
        $string1 = /findstr\s.{0,1000}BEGIN\sCERTIFICATE/ nocase ascii wide
        // Description: findstr used to find credentials
        // Reference: N/A
        $string2 = /findstr\s.{0,1000}confidential/ nocase ascii wide
        // Description: findstr used to find credentials
        // Reference: N/A
        $string3 = /findstr\s.{0,1000}net\suse/ nocase ascii wide
        // Description: findstr used to find credentials
        // Reference: N/A
        $string4 = /findstr\s.{0,1000}password/ nocase ascii wide
        // Description: findstr used to find credentials
        // Reference: N/A
        $string5 = /findstr\s\/S\s\/I\scpassword\s.{0,1000}\\policies\\.{0,1000}\.xml/ nocase ascii wide
        // Description: findstr used to find lsass pid in order to dump lsass process
        // Reference: https://github.com/gabriellandau/PPLFault
        $string6 = /findstr\slsass/ nocase ascii wide

    condition:
        any of them
}
