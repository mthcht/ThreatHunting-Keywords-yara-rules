rule RdpThief
{
    meta:
        description = "Detection patterns for the tool 'RdpThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string1 = "/RdpThief" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string2 = /\/RdpThief\.git/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string3 = /\\RdpThief\./ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string4 = /\\RdpThief_x64\./ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string5 = "0x09AL/RdpThief" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string6 = "71461ca71bcebb5fefa9394fe8e9a5a47c102195064d1f4cb5f24d330c9be97d" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string7 = "ae320a69dd18e08c9cfb026f247978522ffde2acddeff93a5406c9b584dbc430" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string8 = "ae320a69dd18e08c9cfb026f247978522ffde2acddeff93a5406c9b584dbc430" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string9 = "BEBE6A01-0C03-4A7C-8FE9-9285F01C0B03" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string10 = "BEBE6A01-0C03-4A7C-8FE9-9285F01C0B03" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string11 = "cd7e4cd71cb803de24f7b8fc6c6946f96e9b9a95dd3c0888309b42446ba87b94" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string12 = "d0fd70c59cf45c5c1eb9c73ba1ccfa433d715a3a57b1312a26a02c60210cbfb8" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string13 = "d0fd70c59cf45c5c1eb9c73ba1ccfa433d715a3a57b1312a26a02c60210cbfb8" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string14 = "Disabling RdpThief" nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string15 = "RdpThief enabled " nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string16 = /RdpThief\.dll/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string17 = /RdpThief\.exe/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string18 = /RdpThief_x64\.tmp/ nocase ascii wide

    condition:
        any of them
}
