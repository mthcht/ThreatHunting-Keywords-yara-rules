rule rentry_co
{
    meta:
        description = "Detection patterns for the tool 'rentry.co' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rentry.co"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: accessing a pastebinlike site - often abused by malware
        // Reference: N/A
        $string1 = /https\:\/\/rentry\.co\// nocase ascii wide
        // Description: raw format paste access attempt - abused by attackers to store malicious payloads
        // Reference: N/A
        $string2 = /https\:\/\/rentry\.co\/.{0,1000}\/raw/ nocase ascii wide
        // Description: raw format paste access attempt - abused by attackers to store malicious payloads
        // Reference: N/A
        $string3 = /https\:\/\/rentry\.co\/cdn\-cgi\/challenge\-platform\// nocase ascii wide

    condition:
        any of them
}
