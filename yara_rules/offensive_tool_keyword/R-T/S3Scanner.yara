rule S3Scanner
{
    meta:
        description = "Detection patterns for the tool 'S3Scanner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "S3Scanner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string1 = /\sdump\s\-\-bucket\s.{0,1000}\-\-dump\-dir/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string2 = /\s\-\-threads\s.{0,1000}\sscan\s\-\-buckets\-file.{0,1000}\s/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string3 = /\/S3Scanner\.git/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string4 = /install\ss3scanner/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string5 = /python3\s\-m\sS3Scanner/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string6 = /s3scanner\s\-/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string7 = /s3scanner\sdump\s/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string8 = /s3scanner\sscan\s/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string9 = /S3Scanner\-master/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string10 = /sa7mon\/S3Scanner/ nocase ascii wide

    condition:
        any of them
}
