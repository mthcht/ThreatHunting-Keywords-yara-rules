rule RdpStrike
{
    meta:
        description = "Detection patterns for the tool 'RdpStrike' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpStrike"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string1 = /\"RdpStrike\.cna\"/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string2 = /\/RdpStrike\.git/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string3 = /\\RdpStrike\.asm/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string4 = /\\RdpStrike\.cna/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string5 = /\\RdpStrike\\/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string6 = /0xEr3bus\/RdpStrike/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string7 = /227cc3d2c07ef203c39afe00c81943cf245d626c1efa1b32024d7229604635e5/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string8 = /Disabling\sRDPStrike/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string9 = /Injecting\sinto\smstsc\.exe/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string10 = /RDPStrike\senabled/ nocase ascii wide
        // Description: Positional Independent Code to extract clear text password from mstsc.exe using API Hooking via HWBP
        // Reference: https://github.com/0xEr3bus/RdpStrike
        $string11 = /RdpStrike\.x64\.bin/ nocase ascii wide

    condition:
        any of them
}
