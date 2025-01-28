rule pingcastle
{
    meta:
        description = "Detection patterns for the tool 'pingcastle' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pingcastle"
        rule_category = "signature_keyword"

    strings:
        // Description: active directory weakness scan Vulnerability scanner
        // Reference: https://github.com/netwrix/pingcastle
        $string1 = "HackTool:Win32/SmbAgent" nocase ascii wide

    condition:
        any of them
}
