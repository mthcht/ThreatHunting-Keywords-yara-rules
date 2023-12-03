rule rpivot
{
    meta:
        description = "Detection patterns for the tool 'rpivot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rpivot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: socks4 reverse proxy for penetration testing
        // Reference: https://github.com/klsecservices/rpivot
        $string1 = /.{0,1000}\s\-\-ntlm\-proxy\-ip\s.{0,1000}\s\-\-ntlm\-proxy\-port\s.{0,1000}/ nocase ascii wide
        // Description: socks4 reverse proxy for penetration testing
        // Reference: https://github.com/klsecservices/rpivot
        $string2 = /.{0,1000}\/rpivot\.git.{0,1000}/ nocase ascii wide
        // Description: socks4 reverse proxy for penetration testing
        // Reference: https://github.com/klsecservices/rpivot
        $string3 = /.{0,1000}9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45.{0,1000}/ nocase ascii wide
        // Description: socks4 reverse proxy for penetration testing
        // Reference: https://github.com/klsecservices/rpivot
        $string4 = /.{0,1000}client\.py\s\-\-server\-ip\s.{0,1000}\s\-\-server\-port\s.{0,1000}/ nocase ascii wide
        // Description: socks4 reverse proxy for penetration testing
        // Reference: https://github.com/klsecservices/rpivot
        $string5 = /.{0,1000}client\.py.{0,1000}\-\-domain.{0,1000}\-\-hashes.{0,1000}/ nocase ascii wide
        // Description: socks4 reverse proxy for penetration testing
        // Reference: https://github.com/klsecservices/rpivot
        $string6 = /.{0,1000}klsecservices\/rpivot.{0,1000}/ nocase ascii wide
        // Description: socks4 reverse proxy for penetration testing
        // Reference: https://github.com/klsecservices/rpivot
        $string7 = /.{0,1000}rpivot\.zip.{0,1000}/ nocase ascii wide
        // Description: socks4 reverse proxy for penetration testing
        // Reference: https://github.com/klsecservices/rpivot
        $string8 = /.{0,1000}rpivot\-master.{0,1000}/ nocase ascii wide
        // Description: socks4 reverse proxy for penetration testing
        // Reference: https://github.com/klsecservices/rpivot
        $string9 = /.{0,1000}\-\-server\-port\s.{0,1000}\s\-\-server\-ip\s.{0,1000}\s\-\-proxy\-ip\s.{0,1000}\s\-\-proxy\-port\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
