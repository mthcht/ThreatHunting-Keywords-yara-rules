rule homeway_io
{
    meta:
        description = "Detection patterns for the tool 'homeway.io' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "homeway.io"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Expose local servers to the internet
        // Reference: https://homeway.io/
        $string1 = /homeassistant\.local\:8123/ nocase ascii wide
        // Description: Expose local servers to the internet
        // Reference: https://homeway.io/
        $string2 = /https\:\/\/homeway\.io\/install\.sh/ nocase ascii wide

    condition:
        any of them
}
