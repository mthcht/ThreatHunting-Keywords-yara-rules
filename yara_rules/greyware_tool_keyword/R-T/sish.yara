rule sish
{
    meta:
        description = "Detection patterns for the tool 'sish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sish"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string1 = /\ssish\s\-c\sdate/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string2 = /\/_sish\/console/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string3 = /\/sish\.git/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string4 = /\/sish\.log/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string5 = /\/sish\/cmd\// nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string6 = /\\sish\.log/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string7 = /eb0d8e4273608c13b5957ac047f911442b3d55527e20097cd038e120f01df5ae/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string8 = /http\:\/\/.{0,1000}\.ssi\.sh/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string9 = /https\:\/\/.{0,1000}\.ssi\.sh/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string10 = /sish\s\-x/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string11 = /ssh\s\-L\s.{0,1000}\stuns\.sh/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string12 = /ssh\s\-R\s.{0,1000}\stuns\.sh/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string13 = /testing\.ssi\.sh/ nocase ascii wide

    condition:
        any of them
}
