rule http_server
{
    meta:
        description = "Detection patterns for the tool 'http.server' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "http.server"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: setup a simple http server
        // Reference: https://x.com/mthcht/status/1827714529687658796
        $string1 = /python\s\-m\shttp\.server/ nocase ascii wide
        // Description: setup a simple http server
        // Reference: https://x.com/mthcht/status/1827714529687658796
        $string2 = /python3\s\-m\shttp\.server/ nocase ascii wide

    condition:
        any of them
}
