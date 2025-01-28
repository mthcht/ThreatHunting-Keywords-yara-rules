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
        $string1 = "/bin/bash -c 'wg addconf "
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string2 = /\/etc\/wireguard\/.{0,1000}\.conf/
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string3 = "/root/tunnel"
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string4 = "9e3c014399ad61b61a1fa5fa58de95a4ddfded6ff863c413cea089f2d92f9d70"
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string5 = "Overwrite by setting TUNNEL_WG_INTERFACE_NAME"
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string6 = /pyjam\.as\/tunnel/
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string7 = /tunnel\.pyjam\.as/
        // Description: SSL-terminated ephemeral HTTP tunnels to your local machine - no custom software required (thanks to wireguard)
        // Reference: https://gitlab.com/pyjam.as/tunnel
        $string8 = "TUNNEL_WG_INTERFACE_NAME="

    condition:
        any of them
}
