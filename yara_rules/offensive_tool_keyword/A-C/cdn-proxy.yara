rule cdn_proxy
{
    meta:
        description = "Detection patterns for the tool 'cdn-proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cdn-proxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string1 = /cdn_proxy\scloudflare\s/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string2 = /cdn_proxy_burp_ext\.py/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string3 = /cdn\-proxy\s\-/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string4 = /cdn\-proxy\scloudfront\s/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string5 = /cdn\-proxy\.git/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string6 = /cdn\-proxy\/burp_extension/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string7 = /Cdn\-Proxy\-Host/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string8 = /Cdn\-Proxy\-Origin/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string9 = /cdn\-scanner\s\-/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string10 = /install\scdn\-proxy/ nocase ascii wide

    condition:
        any of them
}
