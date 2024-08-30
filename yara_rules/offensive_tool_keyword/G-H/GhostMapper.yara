rule GhostMapper
{
    meta:
        description = "Detection patterns for the tool 'GhostMapper' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GhostMapper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: GhostMapper involves modifying Windows system "dump_" prefix drivers to exploit crash handling mechanisms for malicious purposes.
        // Reference: https://github.com/Oliver-1-1/GhostMapper
        $string1 = /\/GhostMapper\.git/ nocase ascii wide
        // Description: GhostMapper involves modifying Windows system "dump_" prefix drivers to exploit crash handling mechanisms for malicious purposes.
        // Reference: https://github.com/Oliver-1-1/GhostMapper
        $string2 = /\/GhostMapper\.sln/ nocase ascii wide
        // Description: GhostMapper involves modifying Windows system "dump_" prefix drivers to exploit crash handling mechanisms for malicious purposes.
        // Reference: https://github.com/Oliver-1-1/GhostMapper
        $string3 = /\\GhostMapper\.sln/ nocase ascii wide
        // Description: GhostMapper involves modifying Windows system "dump_" prefix drivers to exploit crash handling mechanisms for malicious purposes.
        // Reference: https://github.com/Oliver-1-1/GhostMapper
        $string4 = /4D7BA537\-54EC\-4005\-9CC2\-AE134B4526F9/ nocase ascii wide
        // Description: GhostMapper involves modifying Windows system "dump_" prefix drivers to exploit crash handling mechanisms for malicious purposes.
        // Reference: https://github.com/Oliver-1-1/GhostMapper
        $string5 = /GhostMapper\-main\./ nocase ascii wide
        // Description: GhostMapper involves modifying Windows system "dump_" prefix drivers to exploit crash handling mechanisms for malicious purposes.
        // Reference: https://github.com/Oliver-1-1/GhostMapper
        $string6 = /Oliver\-1\-1\/GhostMapper/ nocase ascii wide

    condition:
        any of them
}
