rule btunnel
{
    meta:
        description = "Detection patterns for the tool 'btunnel' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "btunnel"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string1 = /\/\.btunnel\./ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string2 = /\/btunnel\.exe/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string3 = /\/btunnel\.log/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string4 = /\\\.btunnel\./ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string5 = /\\bored\-tunnel\-client/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string6 = /\\btunnel\.exe/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string7 = /\\btunnel\.log/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string8 = "60e8a9e19b34ca6d9f1847504b7689b3f46b029ab07b4d13c6ccde026d78a0a4" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string9 = "af19236f06140b33ac3c78ae743627ba34dcd89be6d5c8dd22cac7f6eae19774" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string10 = /api\.btunnel\.in/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string11 = /bored\-tunnel\-client_Windows_x86_64\./ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string12 = "btunnel domain " nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string13 = "btunnel file " nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string14 = "btunnel http" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string15 = "btunnel tcp --" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string16 = "btunnel tcp" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string17 = /btunnel\.exe\shttp/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string18 = "eb1395952e6eb92d4f9a2babb56d29ef384d683387c6a990e79d5fe4ba86040f" nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string19 = /http\:\/\/tcp\.btunnel\.in/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string20 = /https\:\/\/.{0,1000}\.btunnel\.co\.in/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string21 = /https\:\/\/.{0,1000}\.btunnel\.co\.in/ nocase ascii wide
        // Description: Btunnel is a publicly accessible reverse proxy
        // Reference: https://www.btunnel.in
        $string22 = /https\:\/\/www\.btunnel\.in\/downloads/ nocase ascii wide

    condition:
        any of them
}
