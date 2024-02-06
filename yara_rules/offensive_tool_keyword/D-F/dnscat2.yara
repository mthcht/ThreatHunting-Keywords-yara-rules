rule dnscat2
{
    meta:
        description = "Detection patterns for the tool 'dnscat2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscat2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string1 = /\.\/dnscat/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string2 = /\/dnscat\.c/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string3 = /\/dnscat2\.git/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string4 = /0\.0\.0\.0\:53531/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string5 = /127\.0\.0\.1\:53531/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string6 = /data\/wordlist_256\.txt/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string7 = /dnscat\s\-/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string8 = /dnscat\stcpcat/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string9 = /dnscat2.{0,1000}\.tar\.bz2/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string10 = /dnscat2\-.{0,1000}\.zip/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string11 = /dnscat2\./ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string12 = /dnscat2\// nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string13 = /dnscat2\-server/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string14 = /dnscat2\-win32\.exe/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string15 = /dnsmastermind\.rb/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string16 = /localhost\:53531/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string17 = /server\=.{0,1000}port\=53531/ nocase ascii wide

    condition:
        any of them
}
