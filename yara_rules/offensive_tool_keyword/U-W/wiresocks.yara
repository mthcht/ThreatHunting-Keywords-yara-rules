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
        $string1 = /.{0,1000}\sredsocks\.sh.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string2 = /.{0,1000}\/redsocks\.sh.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string3 = /.{0,1000}\/redsocks\-fw\.sh.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string4 = /.{0,1000}\/wiresocks\.git.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string5 = /.{0,1000}\-c\s\/tmp\/redsocks\.conf.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string6 = /.{0,1000}docker\-compose\slogs\swiresocks.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string7 = /.{0,1000}iptables\s\-t\snat\s\-A\sREDSOCKS.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string8 = /.{0,1000}redsocks\-fw\.sh\sstop.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string9 = /.{0,1000}sensepost\/wiresocks.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string10 = /.{0,1000}wiresocks\-main.{0,1000}/ nocase ascii wide
        // Description: Docker-compose and Dockerfile to setup a wireguard VPN connection forcing specific TCP traffic through a socks proxy.
        // Reference: https://github.com/sensepost/wiresocks
        $string11 = /.{0,1000}wiresocks\-redsocks.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
