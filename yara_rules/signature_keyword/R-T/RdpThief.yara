rule RdpThief
{
    meta:
        description = "Detection patterns for the tool 'RdpThief' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpThief"
        rule_category = "signature_keyword"

    strings:
        // Description: Extracting Clear Text Passwords from mstsc.exe using API Hooking.
        // Reference: https://github.com/0x09AL/RdpThief
        $string1 = /HackTool\.RdpThief/ nocase ascii wide

    condition:
        any of them
}
