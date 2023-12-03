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
        $string1 = /.{0,1000}\scharlotte\.cpp.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string2 = /.{0,1000}\scharlotte\.dll\s.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string3 = /.{0,1000}\/charlotte\.cpp.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string4 = /.{0,1000}\/charlotte\.py.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string5 = /.{0,1000}\\charlotte\.cpp.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string6 = /.{0,1000}\\charlotte\.py.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string7 = /.{0,1000}9emin1\/charlotte.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string8 = /.{0,1000}charlotte\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string9 = /.{0,1000}http.{0,1000}\/charlotte\.dll.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string10 = /.{0,1000}python.{0,1000}charlotte\.py.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string11 = /.{0,1000}rundll32\scharlotte\.dll.{0,1000}/ nocase ascii wide
        // Description: c++ fully undetected shellcode launcher
        // Reference: https://github.com/9emin1/charlotte
        $string12 = /.{0,1000}windows\/x64\/meterpreter_reverse_tcp.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
