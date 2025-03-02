rule auditd
{
    meta:
        description = "Detection patterns for the tool 'auditd' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "auditd"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: disabling auditd
        // Reference: N/A
        $string1 = "auditctl -e 0"
        // Description: disabling auditd
        // Reference: N/A
        $string2 = "auditctl -e0"
        // Description: disabling auditd
        // Reference: N/A
        $string3 = "systemctl disable auditd"

    condition:
        any of them
}
