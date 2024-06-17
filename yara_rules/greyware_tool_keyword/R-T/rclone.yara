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
        $string2 = /\/rclone\.exe/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string3 = /\\AppData\\Roaming\\rclone\\rclone\.conf/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string4 = /\\rclone\.exe/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string5 = /rclone\s\scopy\s.{0,1000}\:/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string6 = /rclone\scopy\s.{0,1000}\:/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string7 = /rclone\.exe\sconfig\screate\sremote\smega\suser\s/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string8 = /rclone\.exe.{0,1000}\scopy\s.{0,1000}\:/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string9 = /rclone\.exe.{0,1000}\s\-l\s.{0,1000}\s.{0,1000}\:/ nocase ascii wide

    condition:
        any of them
}
