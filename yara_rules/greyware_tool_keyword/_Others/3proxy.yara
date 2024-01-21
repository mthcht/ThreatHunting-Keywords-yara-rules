rule _3proxy
{
    meta:
        description = "Detection patterns for the tool '3proxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "3proxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string1 = /\/3proxy\-.{0,1000}\.deb/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string2 = /\/3proxy\-.{0,1000}\.rpm/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string3 = /\/3proxy\-.{0,1000}\.zip/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string4 = /\/3proxy\.exe/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string5 = /\/3proxy\.git/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string6 = /\/3proxy\.log/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string7 = /\/etc\/3proxy\/conf/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string8 = /\\3proxy\-.{0,1000}\.deb/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string9 = /\\3proxy\-.{0,1000}\.rpm/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string10 = /\\3proxy\-.{0,1000}\.zip/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string11 = /\\3proxy\.cfg/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string12 = /\\3proxy\.exe/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string13 = /\\3proxy\.key/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string14 = /\\3proxy\.log/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string15 = /\\bin\\3proxy/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string16 = /128s3proxy\.key\"/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string17 = /3proxy\s\-\-install/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string18 = /3proxy\s\-\-remove/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string19 = /3proxy\stiny\sproxy\sserver/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string20 = /3proxy\sWindows\sAuthentication\splugin/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string21 = /3proxy\.exe\s\-\-/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string22 = /3proxy\.service/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string23 = /3proxy\/3proxy/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string24 = /3proxy\@3proxy\.org/ nocase ascii wide
        // Description: 3proxy - tiny free proxy server
        // Reference: https://github.com/3proxy/3proxy
        $string25 = /add3proxyuser\.sh/ nocase ascii wide

    condition:
        any of them
}
