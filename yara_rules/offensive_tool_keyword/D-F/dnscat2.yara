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
        $string1 = /.{0,1000}\.\/dnscat.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string2 = /.{0,1000}\/dnscat\.c.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string3 = /.{0,1000}\/dnscat2\.git.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string4 = /.{0,1000}0\.0\.0\.0:53531.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string5 = /.{0,1000}127\.0\.0\.1:53531.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string6 = /.{0,1000}data\/wordlist_256\.txt.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string7 = /.{0,1000}dnscat\s\-.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string8 = /.{0,1000}dnscat\stcpcat.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string9 = /.{0,1000}dnscat2.{0,1000}\.tar\.bz2.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string10 = /.{0,1000}dnscat2\-.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string11 = /.{0,1000}dnscat2\..{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string12 = /.{0,1000}dnscat2\/.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string13 = /.{0,1000}dnscat2\-server.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string14 = /.{0,1000}dnscat2\-win32\.exe.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string15 = /.{0,1000}dnsmastermind\.rb.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string16 = /.{0,1000}localhost:53531.{0,1000}/ nocase ascii wide
        // Description: This tool is designed to create an encrypted command-and-control (C&C) channel over the DNS protocol
        // Reference: https://github.com/iagox86/dnscat2
        $string17 = /.{0,1000}server\=.{0,1000}port\=53531.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
