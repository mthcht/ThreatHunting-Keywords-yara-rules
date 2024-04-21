rule tunnel_pyjam_as
{
    meta:
        description = "Detection patterns for the tool 'tunnel.pyjam.as' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnel.pyjam.as"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string1 = /\/bin\/bash\s\-c\s\'wg\saddconf\s/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string2 = /\/etc\/wireguard\/.{0,1000}\.conf/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string3 = /\/root\/tunnel/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string4 = /9e3c014399ad61b61a1fa5fa58de95a4ddfded6ff863c413cea089f2d92f9d70/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string5 = /Overwrite\sby\ssetting\sTUNNEL_WG_INTERFACE_NAME/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string6 = /pyjam\.as\/tunnel/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string7 = /tunnel\.pyjam\.as/ nocase ascii wide
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string8 = /TUNNEL_WG_INTERFACE_NAME\=/ nocase ascii wide

    condition:
        any of them
}
