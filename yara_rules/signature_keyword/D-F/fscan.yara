rule fscan
{
    meta:
        description = "Detection patterns for the tool 'fscan' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fscan"
        rule_category = "signature_keyword"

    strings:
        // Description: Vulnerability scanner
        // Reference: https://github.com/shadow1ng/fscan
        $string1 = "HackTool:Linux/Fscan"

    condition:
        any of them
}
