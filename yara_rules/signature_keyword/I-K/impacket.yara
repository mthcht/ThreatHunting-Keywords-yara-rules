rule impacket
{
    meta:
        description = "Detection patterns for the tool 'impacket' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacket"
        rule_category = "signature_keyword"

    strings:
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string1 = /HackTool\.Win32\.Mpacket/ nocase ascii wide

    condition:
        any of them
}
