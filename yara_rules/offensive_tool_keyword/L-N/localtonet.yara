rule localtonet
{
    meta:
        description = "Detection patterns for the tool 'localtonet' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "localtonet"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string1 = /\slocaltonet\.service/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string2 = /\/localtonet\.dll/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string3 = /\/localtonet\.exe/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string4 = /\/localtonet\.git/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string5 = /\/localtonet\.service/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string6 = /\/localtonet\-win/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string7 = /\/opt\/localtonet/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string8 = /\\localtonet\.dll/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string9 = /\\localtonet\.exe/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string10 = /\\localtonet\-win/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string11 = /925fe97c66e61207fec6e73bf01385139ccf6a482c234cb63f1bfafa6b260cb7/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string12 = /a82ec4a7feac8a7bcab876286599e1df136c93ac470ba634fa77be156ee40615/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string13 = /\-e\slocaltonet\.service/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string14 = /e27bbd5323fd6e3c1fcd501bf9279dd83fa211892c10ebf552773f4f5c89e4ab/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string15 = /engineseller\/localtonet/ nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string16 = /localtonet\.com\/download\// nocase ascii wide
        // Description: LocaltoNet is a reverse proxy that enables you to expose your localhost services to the internet
        // Reference: https://github.com/engineseller/localtonet
        $string17 = /queue\.localtonet\.com/ nocase ascii wide

    condition:
        any of them
}
