rule Offensive_Netsh_Helper
{
    meta:
        description = "Detection patterns for the tool 'Offensive-Netsh-Helper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Offensive-Netsh-Helper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Maintain Windows Persistence with an evil Netshell Helper DLL
        // Reference: https://github.com/rtcrowley/Offensive-Netsh-Helper
        $string1 = /\/Offensive\-Netsh\-Helper\.git/ nocase ascii wide
        // Description: Maintain Windows Persistence with an evil Netshell Helper DLL
        // Reference: https://github.com/rtcrowley/Offensive-Netsh-Helper
        $string2 = /\\netshlep\.cpp/ nocase ascii wide
        // Description: Maintain Windows Persistence with an evil Netshell Helper DLL
        // Reference: https://github.com/rtcrowley/Offensive-Netsh-Helper
        $string3 = /\\Offensive\-Netsh\-Helper\\/ nocase ascii wide
        // Description: Maintain Windows Persistence with an evil Netshell Helper DLL
        // Reference: https://github.com/rtcrowley/Offensive-Netsh-Helper
        $string4 = /\\Offensive\-Netsh\-Helper\-master/ nocase ascii wide
        // Description: Maintain Windows Persistence with an evil Netshell Helper DLL
        // Reference: https://github.com/rtcrowley/Offensive-Netsh-Helper
        $string5 = /486d59732d2c346aa2cbaffff0d290b0e5fc0a967e0878240fd29df65525dfc8/ nocase ascii wide
        // Description: Maintain Windows Persistence with an evil Netshell Helper DLL
        // Reference: https://github.com/rtcrowley/Offensive-Netsh-Helper
        $string6 = /cwB0AGEAcgB0ACAAYwBhAGwAYwA\=/ nocase ascii wide
        // Description: Maintain Windows Persistence with an evil Netshell Helper DLL
        // Reference: https://github.com/rtcrowley/Offensive-Netsh-Helper
        $string7 = /netsh\sadd\shelper\snetshBad\.DLL/ nocase ascii wide
        // Description: Maintain Windows Persistence with an evil Netshell Helper DLL
        // Reference: https://github.com/rtcrowley/Offensive-Netsh-Helper
        $string8 = /rtcrowley\/Offensive\-Netsh\-Helper/ nocase ascii wide

    condition:
        any of them
}
