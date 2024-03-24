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
        $string1 = /ae320a69dd18e08c9cfb026f247978522ffde2acddeff93a5406c9b584dbc430/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string2 = /BEBE6A01\-0C03\-4A7C\-8FE9\-9285F01C0B03/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string3 = /d0fd70c59cf45c5c1eb9c73ba1ccfa433d715a3a57b1312a26a02c60210cbfb8/ nocase ascii wide
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string4 = /RdpThief/ nocase ascii wide

    condition:
        any of them
}
