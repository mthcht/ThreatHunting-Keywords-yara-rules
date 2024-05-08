rule beeceptor_com
{
    meta:
        description = "Detection patterns for the tool 'beeceptor.com' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "beeceptor.com"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: temporary public URL for your localhost + port combination - ideal for real-time testing - can be abused for payload callback confirmation
        // Reference: https://beeceptor.com/local-tunnel
        $string1 = /https\:\/\/.{0,1000}\.free\.beeceptor\.com/ nocase ascii wide

    condition:
        any of them
}
