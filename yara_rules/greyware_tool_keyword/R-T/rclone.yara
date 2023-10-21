rule rclone
{
    meta:
        description = "Detection patterns for the tool 'rclone' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "rclone"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string1 = /\.rclone\.exe\sconfig/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string2 = /rclone\scopy\s.*:/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string3 = /rclone\.exe\sconfig\screate\sremote\smega\suser\s/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string4 = /rclone\.exe.*\scopy\s.*:/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string5 = /rclone\.exe.*\s\-l\s.*\s.*:/ nocase ascii wide

    condition:
        any of them
}