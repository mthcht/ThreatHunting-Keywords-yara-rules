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
        $string2 = "bucketloot -" nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string3 = "bucketloot https://" nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string4 = /bucketloot\.exe\s\-/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string5 = /bucketloot\.exe\shttps\:\/\// nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string6 = "bucketloot-darwin64"
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string7 = "bucketloot-freebsd64" nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string8 = "BucketLoot-master" nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string9 = "bucketloot-openbsd64" nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string10 = /bucketloot\-windows32\.exe/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string11 = /bucketloot\-windows64\.exe/ nocase ascii wide
        // Description: BucketLoot is an automated S3-compatible bucket inspector that can help users extract assets- flag secret exposures and even search for custom keywords as well as Regular Expressions from publicly-exposed storage buckets by scanning files that store data in plain-text
        // Reference: https://github.com/redhuntlabs/BucketLoot
        $string12 = "redhuntlabs/BucketLoot" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
