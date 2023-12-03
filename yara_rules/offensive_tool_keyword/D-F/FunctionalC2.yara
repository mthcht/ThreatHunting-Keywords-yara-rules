rule FunctionalC2
{
    meta:
        description = "Detection patterns for the tool 'FunctionalC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FunctionalC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string1 = /.{0,1000}\/FunctionalC2\/.{0,1000}/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string2 = /.{0,1000}beacon_endpoint.{0,1000}c2Get.{0,1000}/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string3 = /.{0,1000}beacon_endpoint.{0,1000}c2Post.{0,1000}/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string4 = /.{0,1000}FortyNorthSecurity\/FunctionalC2.{0,1000}/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string5 = /.{0,1000}gcp_functionalc2\.profile.{0,1000}/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string6 = /.{0,1000}http:\/\/.{0,1000}\/FortyNorth\/GetIt.{0,1000}/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string7 = /.{0,1000}http:\/\/.{0,1000}\/FortyNorth\/PostIt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
