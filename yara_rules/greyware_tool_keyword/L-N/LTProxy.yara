rule LTProxy
{
    meta:
        description = "Detection patterns for the tool 'LTProxy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LTProxy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string1 = /\/\.ltproxy\.yml/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string2 = /\/etc\/ltproxy\.yml/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string3 = /\/LTProxy\.git/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string4 = /\/tmp\/\.ltproxy_proxychains_/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string5 = /\\LTProxy\-main/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string6 = /ac5f344727467b6ad9743b8ffa2646ed73180dbdb97224feec6c54c5160a1984/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string7 = /ipt2socks\s\-R\s\-n\s9999\s\-j\s50\s\-u\s.{0,1000}\s\-s\s.{0,1000}\s\-l\s/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string8 = /L\-codes\/LTProxy/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string9 = /ltproxy\srestart/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string10 = /ltproxy\sstart/ nocase ascii wide
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string11 = /ltproxy\sstop/ nocase ascii wide

    condition:
        any of them
}
