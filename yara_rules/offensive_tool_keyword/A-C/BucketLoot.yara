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
        $string1 = /\/BucketLoot\.git/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string2 = /bucketloot\s\-/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string3 = /bucketloot\shttps\:\/\// nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string4 = /bucketloot\.exe\s\-/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string5 = /bucketloot\.exe\shttps\:\/\// nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string6 = /bucketloot\-darwin64/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string7 = /bucketloot\-freebsd64/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string8 = /BucketLoot\-master/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string9 = /bucketloot\-openbsd64/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string10 = /bucketloot\-windows32\.exe/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string11 = /bucketloot\-windows64\.exe/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string12 = /redhuntlabs\/BucketLoot/ nocase ascii wide

    condition:
        any of them
}
