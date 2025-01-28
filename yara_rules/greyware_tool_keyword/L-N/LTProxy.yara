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
        $string1 = /\/\.ltproxy\.yml/
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string2 = /\/etc\/ltproxy\.yml/
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string3 = /\/LTProxy\.git/
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string4 = /\/tmp\/\.ltproxy_proxychains_/
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string5 = /\\LTProxy\-main/
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string6 = "ac5f344727467b6ad9743b8ffa2646ed73180dbdb97224feec6c54c5160a1984"
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string7 = /ipt2socks\s\-R\s\-n\s9999\s\-j\s50\s\-u\s.{0,1000}\s\-s\s.{0,1000}\s\-l\s/
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string8 = "L-codes/LTProxy"
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string9 = "ltproxy restart"
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string10 = "ltproxy start"
        // Description: Linux Transparent Proxy (Similar to Proxifiter)
        // Reference: https://github.com/L-codes/LTProxy
        $string11 = "ltproxy stop"

    condition:
        any of them
}
