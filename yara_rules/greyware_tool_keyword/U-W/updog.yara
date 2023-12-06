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
        $string1 = /\/updog\-.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string2 = /\/updog\.git/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string3 = /\/updog\/archive\/updog\-/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string4 = /\\updog\-master\\/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string5 = /pip.{0,1000}\sinstall\supdog/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string6 = /sc0tfree\/updog/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string7 = /updog\s\-\-/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string8 = /updog\s\-d\s\// nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string9 = /updog\s\-p\s/ nocase ascii wide
        // Description: Updog is a replacement for SimpleHTTPServer. It allows uploading and downloading via HTTP/S can set ad hoc SSL certificates and use http basic auth.
        // Reference: https://github.com/sc0tfree/updog
        $string10 = /updog\-master\.zip/ nocase ascii wide

    condition:
        any of them
}
