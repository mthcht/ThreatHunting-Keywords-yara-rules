rule BucketLoot
{
    meta:
        description = "Detection patterns for the tool 'BucketLoot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BucketLoot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string1 = /.{0,1000}\/BucketLoot\.git.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string2 = /.{0,1000}bucketloot\s\-.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string3 = /.{0,1000}bucketloot\shttps:\/\/.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string4 = /.{0,1000}bucketloot\.exe\s\-.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string5 = /.{0,1000}bucketloot\.exe\shttps:\/\/.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string6 = /.{0,1000}bucketloot\-darwin64.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string7 = /.{0,1000}bucketloot\-freebsd64.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string8 = /.{0,1000}BucketLoot\-master.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string9 = /.{0,1000}bucketloot\-openbsd64.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string10 = /.{0,1000}bucketloot\-windows32\.exe.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string11 = /.{0,1000}bucketloot\-windows64\.exe.{0,1000}/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string12 = /.{0,1000}redhuntlabs\/BucketLoot.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
