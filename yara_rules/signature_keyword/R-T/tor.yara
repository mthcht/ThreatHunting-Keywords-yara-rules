rule tor
{
    meta:
        description = "Detection patterns for the tool 'tor' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tor"
        rule_category = "signature_keyword"

    strings:
        // Description: AV signature for tor binary
        // Reference: N/A
        $string1 = "HackTool:Linux/TorDownload"

    condition:
        any of them
}
