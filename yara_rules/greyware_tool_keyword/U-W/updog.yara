rule updog
{
    meta:
        description = "Detection patterns for the tool 'updog' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "updog"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string1 = /.{0,1000}\/updog\-.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string2 = /.{0,1000}\/updog\.git.{0,1000}/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string3 = /.{0,1000}\/updog\/archive\/updog\-.{0,1000}/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string4 = /.{0,1000}\\updog\-master\\.{0,1000}/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string5 = /.{0,1000}pip.{0,1000}\sinstall\supdog.{0,1000}/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string6 = /.{0,1000}sc0tfree\/updog.{0,1000}/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string7 = /.{0,1000}updog\s\-\-.{0,1000}/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string8 = /.{0,1000}updog\s\-d\s\/.{0,1000}/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string9 = /.{0,1000}updog\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string10 = /.{0,1000}updog\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
