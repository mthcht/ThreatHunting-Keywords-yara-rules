rule dnscat
{
    meta:
        description = "Detection patterns for the tool 'dnscat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dnscat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string1 = /\s\-\-dns\sdomain\=skullseclabs\.org/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string2 = /\.\/dnscat/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string3 = /\/dnscat\.c/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string4 = /\/dnscat2\.git/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string5 = /0\.0\.0\.0\:53531/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string6 = /127\.0\.0\.1\:53531/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string7 = /data\/wordlist_256\.txt/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string8 = "dnscat -"
        // Description: Welcome to dnscat2. a DNS tunnel that WON'T make you sick and kill you This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol. which is an effective tunnel out of almost every network.
        // Reference: https://github.com/iagox86/dnscat2
        $string9 = "dnscat --dns "
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string10 = "dnscat tcpcat"
        // Description: Welcome to dnscat2. a DNS tunnel that WON'T make you sick and kill you This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol. which is an effective tunnel out of almost every network.
        // Reference: https://github.com/iagox86/dnscat2
        $string11 = "dnscat"
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string12 = /dnscat2.{0,1000}\.tar\.bz2/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string13 = /dnscat2\-.{0,1000}\.zip/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string14 = /dnscat2\./
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string15 = "dnscat2/"
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string16 = "dnscat2-server" nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string17 = /dnscat2\-win32\.exe/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string18 = /dnsmastermind\.rb/
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string19 = "localhost:53531"
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string20 = /server\=.{0,1000}port\=53531/

    condition:
        any of them
}
