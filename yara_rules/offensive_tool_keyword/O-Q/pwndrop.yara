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
        $string1 = /.{0,1000}\.\/pwndrop\s.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string2 = /.{0,1000}\/pwndrop\.git.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string3 = /.{0,1000}\/pwndrop\.ini.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string4 = /.{0,1000}\/usr\/local\/pwndrop\/.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string5 = /.{0,1000}kgretzky\/pwndrop.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string6 = /.{0,1000}pwndrop\sinstall.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string7 = /.{0,1000}pwndrop\sstart.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string8 = /.{0,1000}pwndrop\sstatus.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string9 = /.{0,1000}pwndrop\sstop.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string10 = /.{0,1000}pwndrop\-linux\-amd64.{0,1000}/ nocase ascii wide
        // Description: Self-deployable file hosting service for red teamers allowing to easily upload and share payloads over HTTP and WebDAV.
        // Reference: https://github.com/kgretzky/pwndrop
        $string11 = /.{0,1000}pwndrop\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
