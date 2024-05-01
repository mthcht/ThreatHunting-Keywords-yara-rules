rule tunnel
{
    meta:
        description = "Detection patterns for the tool 'tunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string1 = /\sthe\sservers\sWireguard\sinterface\./ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string2 = /\.tunnel\.pyjam\.as/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string3 = /\/\/\sPackage\stunnel\sis\sa\sserver\/client\spackage\sthat\senables\sto\sproxy\spublic/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string4 = /\/etc\/wireguard\/.{0,1000}\.conf/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string5 = /\/etc\/wireguard\/.{0,1000}\.conf/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string6 = /\/pyjam\.as\/tunnel/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string7 = /\/tunnel\/server\.go/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string8 = /\/tunnel\/tunnel\.py/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string9 = /\/tunnel\/tunnel\.service/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string10 = /\/tunnel\-main\.tar\.gz/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string11 = /3579ab708388d7be3e66c1a45deea0f6a249865ce4105310d8fe340ed28accca/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string12 = /447a5e8b424ebc3b82e909ab8c585fda579881ad26c35cba3c32b77896008c62/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string13 = /9e3c014399ad61b61a1fa5fa58de95a4ddfded6ff863c413cea089f2d92f9d70/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string14 = /c9165f1628aa7d5a75b907d71efda4fa4ab1fa8bb2ee12ef86478ef6e2c3e162/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string15 = /e82ae72bb202db9bae86dc81cf4df152b6d8d3b5062295004b8ae92088904dc7/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string16 = /github.{0,1000}koding\/tunnel/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string17 = /http\:\/\/arslan\.koding\.io\// nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string18 = /https\:\/\/tunnel\.pyjam\.as\// nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string19 = /https\:\/\/www\.wireguard\.com\/install/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string20 = /tunnel\/httpproxy\.go/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string21 = /wg\-quick\sdown\s\.\/tunnel\.conf/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string22 = /wg\-quick\sup\s\.\/tunnel\.conf/ nocase ascii wide
        // Description: Tunnel is a server/client package that enables to proxy public connections to your local machine over a tunnel connection from the local machine to the public server. What this means is, you can share your localhost even if it doesn't have a Public IP or if it's not reachable from outside
        // Reference: https://github.com/koding/tunnel
        $string23 = /Write\sWireguard\sserver\sconfiguration\sto\sdisk\./ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string24 = /Write\sWireguard\sserver\sconfiguration\sto\sdisk\./ nocase ascii wide

    condition:
        any of them
}
