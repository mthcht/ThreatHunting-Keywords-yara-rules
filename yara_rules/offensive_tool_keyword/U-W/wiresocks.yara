rule wiresocks
{
    meta:
        description = "Detection patterns for the tool 'wiresocks' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "wiresocks"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string1 = /\sredsocks\.sh/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string2 = /\/redsocks\.sh/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string3 = /\/redsocks\-fw\.sh/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string4 = /\/wiresocks\.git/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string5 = /\-c\s\/tmp\/redsocks\.conf/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string6 = /docker\-compose\slogs\swiresocks/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string7 = /iptables\s\-t\snat\s\-A\sREDSOCKS/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string8 = /redsocks\-fw\.sh\sstop/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string9 = /sensepost\/wiresocks/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string10 = /wiresocks\-main/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string11 = /wiresocks\-redsocks/ nocase ascii wide

    condition:
        any of them
}
