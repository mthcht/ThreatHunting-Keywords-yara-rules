rule mitmproxy
{
    meta:
        description = "Detection patterns for the tool 'mitmproxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mitmproxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An interactive. SSL-capable man-in-the-middle proxy for HTTP with a console interface
        // Reference: https://github.com/mitmproxy/mitmproxy
        $string1 = /6870cfc153e4d1478d4a3907036f32b7ebb1183810375475a436debb584fd8d3/ nocase ascii wide
        // Description: An interactive. SSL-capable man-in-the-middle proxy for HTTP with a console interface
        // Reference: https://github.com/mitmproxy/mitmproxy
        $string2 = /mitmdump/ nocase ascii wide
        // Description: An interactive. SSL-capable man-in-the-middle proxy for HTTP with a console interface
        // Reference: https://github.com/mitmproxy/mitmproxy
        $string3 = /mitmproxy/ nocase ascii wide
        // Description: An interactive. SSL-capable man-in-the-middle proxy for HTTP with a console interface
        // Reference: https://github.com/mitmproxy/mitmproxy
        $string4 = /mitmweb/ nocase ascii wide

    condition:
        any of them
}
