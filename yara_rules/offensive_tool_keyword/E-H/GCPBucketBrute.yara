rule GCPBucketBrute
{
    meta:
        description = "Detection patterns for the tool 'GCPBucketBrute' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "GCPBucketBrute"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A script to enumerate Google Storage buckets. determine what access you have to them. and determine if they can be privilege escalated
        // Reference: https://github.com/RhinoSecurityLabs/GCPBucketBrute
        $string1 = /GCPBucketBrute/ nocase ascii wide

    condition:
        any of them
}
