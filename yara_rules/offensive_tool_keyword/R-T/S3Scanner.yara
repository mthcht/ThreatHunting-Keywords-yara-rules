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
        $string1 = /.{0,1000}\sdump\s\-\-bucket\s.{0,1000}\-\-dump\-dir.{0,1000}/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string2 = /.{0,1000}\s\-\-threads\s.{0,1000}\sscan\s\-\-buckets\-file.{0,1000}\s/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string3 = /.{0,1000}\/S3Scanner\.git.{0,1000}/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string4 = /.{0,1000}install\ss3scanner.{0,1000}/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string5 = /.{0,1000}python3\s\-m\sS3Scanner.{0,1000}/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string6 = /.{0,1000}s3scanner\s\-.{0,1000}/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string7 = /.{0,1000}s3scanner\sdump\s.{0,1000}/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string8 = /.{0,1000}s3scanner\sscan\s.{0,1000}/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string9 = /.{0,1000}S3Scanner\-master.{0,1000}/ nocase ascii wide
        // Description: Scan for open S3 buckets and dump the contents
        // Reference: https://github.com/sa7mon/S3Scanner
        $string10 = /.{0,1000}sa7mon\/S3Scanner.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
