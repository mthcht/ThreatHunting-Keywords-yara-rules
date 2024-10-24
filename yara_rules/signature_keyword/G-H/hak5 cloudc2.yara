rule hak5_cloudc2
{
    meta:
        description = "Detection patterns for the tool 'hak5 cloudc2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hak5 cloudc2"
        rule_category = "signature_keyword"

    strings:
        // Description: Cloud C2 makes it easy for pentesters and security teams to deploy and manage Hak5 gear from the cloud
        // Reference: https://shop.hak5.org/products/c2?
        $string1 = /Hacktool\.Hakc2/ nocase ascii wide
        // Description: Cloud C2 makes it easy for pentesters and security teams to deploy and manage Hak5 gear from the cloud
        // Reference: https://shop.hak5.org/products/c2?
        $string2 = /Hacktool\.ZIP\.HakC2/ nocase ascii wide
        // Description: Cloud C2 makes it easy for pentesters and security teams to deploy and manage Hak5 gear from the cloud
        // Reference: https://shop.hak5.org/products/c2?
        $string3 = /Riskware\.Hakc2/ nocase ascii wide
        // Description: Cloud C2 makes it easy for pentesters and security teams to deploy and manage Hak5 gear from the cloud
        // Reference: https://shop.hak5.org/products/c2?
        $string4 = /Riskware\/Hakc2/ nocase ascii wide
        // Description: Cloud C2 makes it easy for pentesters and security teams to deploy and manage Hak5 gear from the cloud
        // Reference: https://shop.hak5.org/products/c2?
        $string5 = /Trojan\/Win32\.Hakc2/ nocase ascii wide

    condition:
        any of them
}
