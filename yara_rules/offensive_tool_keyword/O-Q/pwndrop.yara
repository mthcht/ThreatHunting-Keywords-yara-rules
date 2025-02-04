rule pwndrop
{
    meta:
        description = "Detection patterns for the tool 'pwndrop' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pwndrop"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string1 = /\.\/pwndrop\s/
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string2 = /\/pwndrop\.git/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string3 = /\/pwndrop\.ini/
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string4 = "/usr/local/pwndrop/"
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string5 = "kgretzky/pwndrop" nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string6 = "pwndrop install" nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string7 = "pwndrop start" nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string8 = "pwndrop status" nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string9 = "pwndrop stop" nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string10 = "pwndrop-linux-amd64"
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string11 = "pwndrop-master" nocase ascii wide

    condition:
        any of them
}
