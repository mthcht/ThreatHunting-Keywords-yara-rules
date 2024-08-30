rule gpg
{
    meta:
        description = "Detection patterns for the tool 'gpg' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gpg"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: List gpg keys for privilege escalation
        // Reference: N/A
        $string1 = /gpg\s\-\-list\-keys/ nocase ascii wide

    condition:
        any of them
}
