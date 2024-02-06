rule rsockstun
{
    meta:
        description = "Detection patterns for the tool 'rsockstun' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rsockstun"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: reverse socks tunneler with ntlm and proxy support
        // Reference: https://github.com/llkat/rsockstun
        $string1 = /\s\-listen\s\:.{0,1000}\s\-socks\s.{0,1000}\s\-cert\s.{0,1000}\s\-agentpassword\s/ nocase ascii wide
        // Description: reverse socks tunneler with ntlm and proxy support
        // Reference: https://github.com/llkat/rsockstun
        $string2 = /\.\/rsockstun/ nocase ascii wide
        // Description: reverse socks tunneler with ntlm and proxy support
        // Reference: https://github.com/llkat/rsockstun
        $string3 = /\/rsockstun\s/ nocase ascii wide
        // Description: reverse socks tunneler with ntlm and proxy support
        // Reference: https://github.com/llkat/rsockstun
        $string4 = /\/rsockstun\.git/ nocase ascii wide
        // Description: reverse socks tunneler with ntlm and proxy support
        // Reference: https://github.com/llkat/rsockstun
        $string5 = /llkat\/rsockstun/ nocase ascii wide
        // Description: reverse socks tunneler with ntlm and proxy support
        // Reference: https://github.com/llkat/rsockstun
        $string6 = /RocksDefaultRequestRocksDefaultRequestRocksDefaultRequestRocks/ nocase ascii wide
        // Description: reverse socks tunneler with ntlm and proxy support
        // Reference: https://github.com/llkat/rsockstun
        $string7 = /rsockstun\s\-/ nocase ascii wide
        // Description: reverse socks tunneler with ntlm and proxy support
        // Reference: https://github.com/llkat/rsockstun
        $string8 = /rsockstun\-1\.1\.zip/ nocase ascii wide
        // Description: reverse socks tunneler with ntlm and proxy support
        // Reference: https://github.com/llkat/rsockstun
        $string9 = /rsockstun\-master/ nocase ascii wide

    condition:
        any of them
}
