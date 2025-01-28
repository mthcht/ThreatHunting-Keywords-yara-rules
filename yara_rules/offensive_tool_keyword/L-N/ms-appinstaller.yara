rule ms_appinstaller
{
    meta:
        description = "Detection patterns for the tool 'ms-appinstaller' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ms-appinstaller"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: download cradle with appinstaller from github
        // Reference: N/A
        $string1 = /start\sms\-appinstaller\:\/\/\?source\=https\:\/\/raw\.githubusercontent\.com/ nocase ascii wide

    condition:
        any of them
}
