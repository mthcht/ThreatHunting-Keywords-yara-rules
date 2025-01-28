rule logman
{
    meta:
        description = "Detection patterns for the tool 'logman' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "logman"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: disables Microsoft-Windows-PowerShell event logging until a reboot occurs or the attacker restores the ETW provider
        // Reference: N/A
        $string1 = "logman update trace EventLog-Application --p Microsoft-Windows-PowerShell -ets" nocase ascii wide

    condition:
        any of them
}
