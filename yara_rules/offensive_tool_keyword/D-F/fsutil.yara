rule fsutil
{
    meta:
        description = "Detection patterns for the tool 'fsutil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "fsutil"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Disables antivirus filtering on the developer drive
        // Reference: https://x.com/0gtweet/status/1720532496847167784
        $string1 = /fsutil\sdevdrv\senable\s\/disallowAv/ nocase ascii wide

    condition:
        any of them
}
