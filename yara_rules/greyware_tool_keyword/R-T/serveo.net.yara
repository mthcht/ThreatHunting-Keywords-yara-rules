rule serveo_net
{
    meta:
        description = "Detection patterns for the tool 'serveo.net' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "serveo.net"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Expose local servers to the internet
        // Reference: https://serveo.net
        $string1 = /http\:\/\/.{0,1000}\.serveo\.net/ nocase ascii wide
        // Description: Expose local servers to the internet
        // Reference: https://serveo.net
        $string2 = /https\:\/\/.{0,1000}\.serveo\.net/ nocase ascii wide

    condition:
        any of them
}
