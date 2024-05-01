rule hypertunnel
{
    meta:
        description = "Detection patterns for the tool 'hypertunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hypertunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string1 = /\/hypertunnel\.git/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string2 = /\/hypertunnel\-tcp\-relay.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string3 = /\/hypertunnel\-tcp\-relay.{0,1000}\.zip/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string4 = /23fe91b0f562494d22d23a02a05f35847520170930ceb92cffa6783229b46d78/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string5 = /berstend\/hypertunnel/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string6 = /https\:\/\/hypertunnel\.ga/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string7 = /hypertunnel\.lvh\.me/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string8 = /hypertunnel\-server\@latest/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string9 = /local\.hypertunnel\.lvh\.me/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string10 = /MIIJKgIBAAKCAgEAuvAs1YNtpCaqyG3Rkyutst3uIjzYLQTPWf1v\+OLi3GgzshUB/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string11 = /npm\sinstall\shypertunnel\-server/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string12 = /packages\/hypertunnel\// nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string13 = /packages\/hypertunnel\-server/ nocase ascii wide
        // Description: Expose any local TCP/IP service on the internet
        // Reference: https://github.com/berstend/hypertunnel
        $string14 = /packages\/hypertunnel\-tcp\-relay/ nocase ascii wide

    condition:
        any of them
}
