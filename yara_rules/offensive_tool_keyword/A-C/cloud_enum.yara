rule cloud_enum
{
    meta:
        description = "Detection patterns for the tool 'cloud_enum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloud_enum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string1 = /\scloud_enum\.py/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string2 = /\/cloud_enum\.git/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string3 = /\/cloud_enum\.py/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string4 = /\/cloud_enum\.txt/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string5 = /\\cloud_enum\.py/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string6 = /cloud_enum\-master\.zip/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string7 = /initstring\/cloud_enum/ nocase ascii wide

    condition:
        any of them
}
