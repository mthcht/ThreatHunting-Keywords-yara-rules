rule impacket
{
    meta:
        description = "Detection patterns for the tool 'impacket' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacket"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string1 = /cmd\.exe\s\/Q\s\/c\sdir\s1\>\s.{0,1000}\s2\>\&1\s\&\&\scertutil\s\-encodehex\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string2 = /cmd\.exe\s\/Q\s\/c\shostname\s1\>\s.{0,1000}\s2\>\&1\s\&\&\scertutil\s\-encodehex\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string3 = /cmd\.exe\s\/Q\s\/c\shostname\s1\>\s.{0,1000}\s2\>\&1\s\&\&\scertutil\s\-encodehex\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string4 = /cmd\.exe\s\/Q\s\/c\sipconfig\s1\>\s.{0,1000}\s2\>\&1\s\&\&\scertutil\s\-encodehex\s.{0,1000}\s\s\s\s\s/ nocase ascii wide
        // Description: Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself
        // Reference: https://github.com/fortra/impacket
        $string5 = /cmd\.exe\s\/Q\s\/c\sipconfig\s1\>\s\\Windows\\Temp\\.{0,1000}\s2\>\&1/ nocase ascii wide

    condition:
        any of them
}
