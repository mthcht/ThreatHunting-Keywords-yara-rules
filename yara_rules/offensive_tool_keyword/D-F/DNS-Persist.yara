rule DNS_Persist
{
    meta:
        description = "Detection patterns for the tool 'DNS-Persist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DNS-Persist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string1 = /.{0,1000}\/DNS\-Persist\/.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string2 = /.{0,1000}0x09AL\/DNS\-Persist.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string3 = /.{0,1000}agent.{0,1000}DNSCommunication\.cpp.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string4 = /.{0,1000}DNS\-C2\s\#\>.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string5 = /.{0,1000}DNSListener\.py.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string6 = /.{0,1000}DNS\-Persist\.git.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string7 = /.{0,1000}do_bypassuac.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string8 = /.{0,1000}execute_shellcode\s.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string9 = /.{0,1000}import\sDNSListener.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string10 = /.{0,1000}keylog_dump.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string11 = /.{0,1000}keylog_start.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string12 = /.{0,1000}keylog_stop.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string13 = /.{0,1000}persist\sexceladdin.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string14 = /.{0,1000}persist\slogonscript.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string15 = /.{0,1000}persist\srunkey.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string16 = /.{0,1000}Persistence\.cpp.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string17 = /.{0,1000}Persistence\.exe.{0,1000}/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string18 = /.{0,1000}Shellcode\sInjected\sSuccessfully.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
