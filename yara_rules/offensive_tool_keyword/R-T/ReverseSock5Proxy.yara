rule ReverseSock5Proxy
{
    meta:
        description = "Detection patterns for the tool 'ReverseSock5Proxy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ReverseSock5Proxy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string1 = /\/ReverseSock5Proxy\.git/ nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string2 = "/ReverseSock5Proxy/tarball/" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string3 = "/ReverseSock5Proxy/zipball/" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string4 = /\/SOCK5Server\.cpp/ nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string5 = /\\C2Config\.ini/ nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string6 = "0fdef22052732301186410ad11b9b5f63dfed89e9a35f431b5195cc4387ac918" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string7 = "49340cc563c7fa1b0ee0aa45f9ef1ec227713e1bc56f9c184af0323e425119c1" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string8 = "9db2d93288d2a07ec088c5b123cac2754a0a9ea5221e784eefedf96aca886a17" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string9 = "Application::C2Sock" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string10 = "C2ServerThreadTerminated" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string11 = "Coldroot Sock5 Server" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string12 = "Coldzer0/ReverseSock5Proxy" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string13 = /ConfigIni\:\:GetInt\(\\"\\"Server\\"\\"\,\s\\"\\"SOCK5Port\\"\\"\,\s9090\\"/ nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string14 = "d6fea46b2c10f12284b38995e9b6cee32b2122ea9ba65c00c0c3cc5eb7448e5d" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string15 = "fa00de3a5f4f0fd4f20a4c8cac94e67c13508d45f35d19ea5e4847c2a7a48814" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string16 = "ReverseSock5Proxy/releases/download/" nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string17 = /SendBuffer\(C2Socket/ nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string18 = /Sock5\/Sock5RServer\.h/ nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string19 = /SOCK5Server\.exe/ nocase ascii wide
        // Description: A tiny Reverse Sock5 Proxy
        // Reference: https://github.com/Coldzer0/ReverseSock5Proxy
        $string20 = /SOCK5Server_v0\.0\.1\.zip/ nocase ascii wide

    condition:
        any of them
}
