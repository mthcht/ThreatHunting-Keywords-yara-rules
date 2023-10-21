rule godoh
{
    meta:
        description = "Detection patterns for the tool 'godoh' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "godoh"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string1 = /\/cmd\/c2\.go/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string2 = /\/goDoH\.git/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string3 = /\/godoh\// nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string4 = /godoh\s\-/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string5 = /godoh\sagent/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string6 = /godoh\sc2/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string7 = /godoh\shelp/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string8 = /godoh\sreceive/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string9 = /godoh\ssend/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string10 = /godoh\stest/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string11 = /godoh\-darwin64/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string12 = /godoh\-linux64/ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string13 = /godoh\-windows32\./ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string14 = /godoh\-windows64\./ nocase ascii wide
        // Description: godoh is a proof of concept Command and Control framework. written in Golang. that uses DNS-over-HTTPS as a transport medium. Currently supported providers include Google. Cloudflare but also contains the ability to use traditional DNS.
        // Reference: https://github.com/sensepost/godoh
        $string15 = /sensepost\/goDoH/ nocase ascii wide

    condition:
        any of them
}