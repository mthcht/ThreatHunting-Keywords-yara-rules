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
        $string7 = /0f8802e2c560ffe447ecaf7e88b9a7a0ac526c8e13b382822f9b4eba16c744a2/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string8 = /3f4a0c9d63796dc8d7d2bb3947edf3a2722c9e783e7c7fdfa7e13f2b43eafdc3/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string9 = /4146c24d1d9cfa4c6c019fe4a0bd22f7b5d18086b18b7a74a0965e16e7f94bef/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string10 = /5afdada4e30699db8a1903e8a57fb9b50783299b1a8606f145a56e15fa1a9521/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string11 = /87ae04b11731fe410b0e3bc87e6c99150dc9ba79bfcbd0ec4bf368930e6e2e7b/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string12 = /93eabc4b534f92a5532322bbcc461a04abbb0c32c3c4957c258fd77f451e3b52/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string13 = /aa52afe3cfd41aa6bdc1601a8f5a8dc2f0cac8a7af2cc162bd569082a12aaefa/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string14 = /ab7c24fe58442c46ea47fe89b2b967d733d3a35e2f363af15ddfc82c6f680509/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string15 = /antoniomika\/sish/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string16 = /e3e70157c3a75c549870c5f2796a64c8de05c3d9f71fbcf76239f07875bff829/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string17 = /eb0d8e4273608c13b5957ac047f911442b3d55527e20097cd038e120f01df5ae/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string18 = /http\:\/\/.{0,1000}\.ssi\.sh/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string19 = /https\:\/\/.{0,1000}\.ssi\.sh/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string20 = /sish\s\-x/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string21 = /ssh\s\-L\s.{0,1000}\stuns\.sh/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string22 = /ssh\s\-R\s.{0,1000}\stuns\.sh/ nocase ascii wide
        // Description: HTTP(S)/WS(S)/TCP Tunnels to localhost using only SSH.
        // Reference: https://github.com/antoniomika/sish
        $string23 = /testing\.ssi\.sh/ nocase ascii wide

    condition:
        any of them
}
