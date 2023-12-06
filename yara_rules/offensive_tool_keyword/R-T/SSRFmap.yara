rule SSRFmap
{
    meta:
        description = "Detection patterns for the tool 'SSRFmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SSRFmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Automatic SSRF fuzzer and exploitation tool
        // Reference: https://github.com/swisskyrepo/SSRFmap
        $string1 = /\s\-r\sdata\/.{0,1000}\s\-p\s.{0,1000}\s\-m\sreadfiles.{0,1000}portscan/ nocase ascii wide
        // Description: Automatic SSRF fuzzer and exploitation tool
        // Reference: https://github.com/swisskyrepo/SSRFmap
        $string2 = /\/SSRFmap/ nocase ascii wide
        // Description: SSRF are often used to leverage actions on other services. this framework aims to find and exploit these services easily. SSRFmap takes a Burp request file as input and a parameter to fuzz.
        // Reference: https://github.com/swisskyrepo/SSRFmap
        $string3 = /SSRFmap/ nocase ascii wide
        // Description: Automatic SSRF fuzzer and exploitation tool
        // Reference: https://github.com/swisskyrepo/SSRFmap
        $string4 = /ssrfmap\.py/ nocase ascii wide

    condition:
        any of them
}
