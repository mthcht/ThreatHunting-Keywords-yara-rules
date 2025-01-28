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
        $string1 = "/DNS-Persist/" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string2 = "0x09AL/DNS-Persist" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string3 = /agent.{0,1000}DNSCommunication\.cpp/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string4 = "DNS-C2 #>" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string5 = /DNSListener\.py/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string6 = /DNS\-Persist\.git/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string7 = "do_bypassuac" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string8 = "execute_shellcode " nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string9 = "import DNSListener" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string10 = "keylog_dump" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string11 = "keylog_start" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string12 = "keylog_stop" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string13 = "persist exceladdin" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string14 = "persist logonscript" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string15 = "persist runkey" nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string16 = /Persistence\.exe/ nocase ascii wide
        // Description: DNS-Persist is a post-exploitation agent which uses DNS for command and control.
        // Reference: https://github.com/0x09AL/DNS-Persist
        $string17 = "Shellcode Injected Successfully" nocase ascii wide

    condition:
        any of them
}
