rule ActiveScanPlusPlus
{
    meta:
        description = "Detection patterns for the tool 'ActiveScanPlusPlus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ActiveScanPlusPlus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ActiveScan++ extends Burp Suite's active and passive scanning capabilities. Designed to add minimal network overhead. it identifies application behaviour that may be of interest to advanced testers
        // Reference: https://github.com/albinowax/ActiveScanPlusPlus
        $string1 = /.{0,1000}\/ActiveScanPlusPlus.{0,1000}/ nocase ascii wide
        // Description: ActiveScan++ extends Burp Suite's active and passive scanning capabilities. Designed to add minimal network overhead. it identifies application behaviour that may be of interest to advanced testers
        // Reference: https://github.com/albinowax/ActiveScanPlusPlus
        $string2 = /.{0,1000}activeScan\+\+\.py.{0,1000}/ nocase ascii wide
        // Description: ActiveScan++ extends Burp Suite's active and passive scanning capabilities. Designed to add minimal network overhead. it identifies application behaviour that may be of interest to advanced testers
        // Reference: https://github.com/albinowax/ActiveScanPlusPlus
        $string3 = /.{0,1000}from\sburp\simport\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
