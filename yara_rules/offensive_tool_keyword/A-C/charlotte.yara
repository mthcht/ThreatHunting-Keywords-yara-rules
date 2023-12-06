rule charlotte
{
    meta:
        description = "Detection patterns for the tool 'charlotte' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "charlotte"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string1 = /\scharlotte\.cpp/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string2 = /\scharlotte\.dll\s/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string3 = /\/charlotte\.cpp/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string4 = /\/charlotte\.py/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string5 = /\\charlotte\.cpp/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string6 = /\\charlotte\.py/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string7 = /9emin1\/charlotte/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string8 = /charlotte\-main\.zip/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string9 = /http.{0,1000}\/charlotte\.dll/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string10 = /python.{0,1000}charlotte\.py/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string11 = /rundll32\scharlotte\.dll/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string12 = /windows\/x64\/meterpreter_reverse_tcp/ nocase ascii wide

    condition:
        any of them
}
