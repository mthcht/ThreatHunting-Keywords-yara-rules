rule telegram
{
    meta:
        description = "Detection patterns for the tool 'telegram' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "telegram"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: telegram API usage -given the increasing adoption of Telegram by malware for command and control (C2) operations. it's essential to monitor and restrict its usage within corporate networks and on company devices
        // Reference: api.telegram.org
        $string1 = /api\.telegram\.org/ nocase ascii wide

    condition:
        any of them
}
