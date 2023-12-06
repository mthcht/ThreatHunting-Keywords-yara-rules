rule dtd_finder
{
    meta:
        description = "Detection patterns for the tool 'dtd-finder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dtd-finder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Identify DTDs on filesystem snapshot and build XXE payloads using those local DTDs.
        // Reference: https://github.com/GoSecure/dtd-finder
        $string1 = /dtd\-finder/ nocase ascii wide

    condition:
        any of them
}
