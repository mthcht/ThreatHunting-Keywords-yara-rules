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
        $string1 = /.{0,1000}findstr\s.{0,1000}BEGIN\sCERTIFICATE.{0,1000}/ nocase ascii wide
        // Description: findstr used to find credentials
        // Reference: N/A
        $string2 = /.{0,1000}findstr\s.{0,1000}confidential.{0,1000}/ nocase ascii wide
        // Description: findstr used to find credentials
        // Reference: N/A
        $string3 = /.{0,1000}findstr\s.{0,1000}net\suse.{0,1000}/ nocase ascii wide
        // Description: findstr used to find credentials
        // Reference: N/A
        $string4 = /.{0,1000}findstr\s.{0,1000}password.{0,1000}/ nocase ascii wide
        // Description: findstr used to find lsass pid in order to dump lsass process
        // Reference: https://github.com/gabriellandau/PPLFault
        $string5 = /.{0,1000}findstr\slsass.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
