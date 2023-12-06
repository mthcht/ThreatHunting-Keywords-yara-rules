rule Modlishka_
{
    meta:
        description = "Detection patterns for the tool 'Modlishka ' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Modlishka "
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow.  which allows to transparently proxy multi-domain destination traffic.  both TLS and non-TLS.  over a single domain.  without a requirement of installing any additional certificate on the client.
        // Reference: https://github.com/drk1wi/Modlishka
        $string1 = /\s\-config\smodlishka\.json\s/ nocase ascii wide
        // Description: Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow.  which allows to transparently proxy multi-domain destination traffic.  both TLS and non-TLS.  over a single domain.  without a requirement of installing any additional certificate on the client.
        // Reference: https://github.com/drk1wi/Modlishka
        $string2 = /\/Modlishka\.git/ nocase ascii wide
        // Description: Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow.  which allows to transparently proxy multi-domain destination traffic.  both TLS and non-TLS.  over a single domain.  without a requirement of installing any additional certificate on the client.
        // Reference: https://github.com/drk1wi/Modlishka
        $string3 = /drk1wi\/Modlishka/ nocase ascii wide
        // Description: Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow.  which allows to transparently proxy multi-domain destination traffic.  both TLS and non-TLS.  over a single domain.  without a requirement of installing any additional certificate on the client.
        // Reference: https://github.com/drk1wi/Modlishka
        $string4 = /Modlishka\/config/ nocase ascii wide
        // Description: Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow.  which allows to transparently proxy multi-domain destination traffic.  both TLS and non-TLS.  over a single domain.  without a requirement of installing any additional certificate on the client.
        // Reference: https://github.com/drk1wi/Modlishka
        $string5 = /MODLISHKA_BIN/ nocase ascii wide
        // Description: Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow.  which allows to transparently proxy multi-domain destination traffic.  both TLS and non-TLS.  over a single domain.  without a requirement of installing any additional certificate on the client.
        // Reference: https://github.com/drk1wi/Modlishka
        $string6 = /Modlishka\-linux\-amd64/ nocase ascii wide
        // Description: Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow.  which allows to transparently proxy multi-domain destination traffic.  both TLS and non-TLS.  over a single domain.  without a requirement of installing any additional certificate on the client.
        // Reference: https://github.com/drk1wi/Modlishka
        $string7 = /Modlishka\-windows\-.{0,1000}\-amd64\.exe/ nocase ascii wide
        // Description: Modlishka is a powerful and flexible HTTP reverse proxy. It implements an entirely new and interesting approach of handling browser-based HTTP traffic flow.  which allows to transparently proxy multi-domain destination traffic.  both TLS and non-TLS.  over a single domain.  without a requirement of installing any additional certificate on the client.
        // Reference: https://github.com/drk1wi/Modlishka
        $string8 = /proxy_linux_amd64/ nocase ascii wide

    condition:
        any of them
}
