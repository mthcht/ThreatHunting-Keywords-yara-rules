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
        $string1 = /.{0,1000}cdn_proxy\scloudflare\s/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string2 = /.{0,1000}cdn_proxy_burp_ext\.py.{0,1000}/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string3 = /.{0,1000}cdn\-proxy\s\-.{0,1000}/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string4 = /.{0,1000}cdn\-proxy\scloudfront\s.{0,1000}/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string5 = /.{0,1000}cdn\-proxy\.git.{0,1000}/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string6 = /.{0,1000}cdn\-proxy\/burp_extension.{0,1000}/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string7 = /.{0,1000}Cdn\-Proxy\-Host.{0,1000}/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string8 = /.{0,1000}Cdn\-Proxy\-Origin.{0,1000}/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string9 = /.{0,1000}cdn\-scanner\s\-.{0,1000}/ nocase ascii wide
        // Description: cdn-proxy is a set of tools for bypassing IP allow listing intended to restrict origin access to requests originating from shared CDNs.
        // Reference: https://github.com/RyanJarv/cdn-proxy
        $string10 = /.{0,1000}install\scdn\-proxy.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
