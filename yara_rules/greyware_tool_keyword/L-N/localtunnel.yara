rule localtunnel
{
    meta:
        description = "Detection patterns for the tool 'localtunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string1 = /\s\-\-name\slocaltunnel\s/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/localtunnel/localtunnel
        $string2 = /\.localltunnel\.me/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string3 = /\/go\-localtunnel\.git/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string4 = /\/gotunnelme\.git/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/localtunnel/localtunnel
        $string5 = /\/localtunnel\.git/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/localtunnel/localtunnel
        $string6 = /\/localtunnel\.js/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string7 = /d0274f036468ef236d3a526bb6235289bdbe4c8828ee7feee1829a026f5f3bec/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/localtunnel/localtunnel
        $string8 = /e367bbc84b75901ae680472b7b848ee4f10fbc356e7dd8de5c2c46000cf78818/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string9 = /gotunnelme\s/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/localtunnel/localtunnel
        $string10 = /https\:\/\/localtunnel\.me/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/localtunnel/localtunnel
        $string11 = /install\s\-g\slocaltunnel/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string12 = /localtunnel\/go\-localtunnel/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string13 = /localtunnel\/server\.git/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string14 = /localtunnel\-server\:latest/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string15 = /NoahShen\/gotunnelme/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/localtunnel/localtunnel
        $string16 = /npx\slocaltunnel\s/ nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/NoahShen/gotunnelme
        $string17 = /src\/gotunnelme\// nocase ascii wide
        // Description: localtunnel exposes your localhost to the world
        // Reference: https://github.com/localtunnel/localtunnel
        $string18 = /yarn\sadd\slocaltunnel/ nocase ascii wide

    condition:
        any of them
}
