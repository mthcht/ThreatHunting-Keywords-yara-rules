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
        $string1 = /\/FunctionalC2\// nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string2 = /beacon_endpoint.*c2Get/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string3 = /beacon_endpoint.*c2Post/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string4 = /FortyNorthSecurity\/FunctionalC2/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string5 = /gcp_functionalc2\.profile/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string6 = /http:\/\/.*\/FortyNorth\/GetIt/ nocase ascii wide
        // Description: A small POC of using Azure Functions to relay communications
        // Reference: https://github.com/FortyNorthSecurity/FunctionalC2
        $string7 = /http:\/\/.*\/FortyNorth\/PostIt/ nocase ascii wide

    condition:
        any of them
}