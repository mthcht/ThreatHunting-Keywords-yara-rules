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
        $string1 = /.{0,1000}\.rclone\.exe\sconfig.{0,1000}/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string2 = /.{0,1000}\/rclone\.exe.{0,1000}/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string3 = /.{0,1000}\\rclone\.exe.{0,1000}/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string4 = /.{0,1000}rclone\scopy\s.{0,1000}:.{0,1000}/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string5 = /.{0,1000}rclone\.exe\sconfig\screate\sremote\smega\suser\s.{0,1000}/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string6 = /.{0,1000}rclone\.exe.{0,1000}\scopy\s.{0,1000}:.{0,1000}/ nocase ascii wide
        // Description: rclone abused by threat actors for data exfiltration
        // Reference: https://github.com/rclone/rclone
        $string7 = /.{0,1000}rclone\.exe.{0,1000}\s\-l\s.{0,1000}\s.{0,1000}:.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
