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
        $string1 = /.{0,1000}\scloud_enum\.py.{0,1000}/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string2 = /.{0,1000}\/cloud_enum\.git.{0,1000}/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string3 = /.{0,1000}\/cloud_enum\.py.{0,1000}/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string4 = /.{0,1000}\/cloud_enum\.txt.{0,1000}/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string5 = /.{0,1000}\\cloud_enum\.py.{0,1000}/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string6 = /.{0,1000}cloud_enum\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: Multi-cloud OSINT tool. Enumerate public resources in AWS Azure and Google Cloud.
        // Reference: https://github.com/initstring/cloud_enum
        $string7 = /.{0,1000}initstring\/cloud_enum.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
