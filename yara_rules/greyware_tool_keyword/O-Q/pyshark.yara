rule pyshark
{
    meta:
        description = "Detection patterns for the tool 'pyshark' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pyshark"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string1 = /\/pyshark\.git/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string2 = /\\pyshark\\src\\/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string3 = /import\spyshark/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string4 = /KimiNewt\/pyshark/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string5 = /pip\sinstall\spyshark/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string6 = /pyshark\.FileCapture\(/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string7 = /pyshark\.LiveCapture\(/ nocase ascii wide
        // Description: Python wrapper for tshark allowing python packet parsing using wireshark dissectors
        // Reference: https://github.com/KimiNewt/pyshark
        $string8 = /pyshark\.RemoteCapture\(/ nocase ascii wide

    condition:
        any of them
}
