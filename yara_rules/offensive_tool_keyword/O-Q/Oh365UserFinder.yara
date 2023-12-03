rule Oh365UserFinder
{
    meta:
        description = "Detection patterns for the tool 'Oh365UserFinder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Oh365UserFinder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Oh365UserFinder is used for identifying valid o365 accounts and domains without the risk of account lockouts. The tool parses responses to identify the IfExistsResult flag is null or not. and responds appropriately if the user is valid. The tool will attempt to identify false positives based on response. and either automatically create a waiting period to allow the throttling value to reset. or warn the user to increase timeouts between attempts.
        // Reference: https://github.com/dievus/Oh365UserFinder
        $string1 = /.{0,1000}\/Oh365UserFinder.{0,1000}/ nocase ascii wide
        // Description: Oh365UserFinder is used for identifying valid o365 accounts and domains without the risk of account lockouts. The tool parses responses to identify the IfExistsResult flag is null or not. and responds appropriately if the user is valid. The tool will attempt to identify false positives based on response. and either automatically create a waiting period to allow the throttling value to reset. or warn the user to increase timeouts between attempts.
        // Reference: https://github.com/dievus/Oh365UserFinder
        $string2 = /.{0,1000}Oh365UserFinder\.git.{0,1000}/ nocase ascii wide
        // Description: Oh365UserFinder is used for identifying valid o365 accounts and domains without the risk of account lockouts. The tool parses responses to identify the IfExistsResult flag is null or not. and responds appropriately if the user is valid. The tool will attempt to identify false positives based on response. and either automatically create a waiting period to allow the throttling value to reset. or warn the user to increase timeouts between attempts.
        // Reference: https://github.com/dievus/Oh365UserFinder
        $string3 = /.{0,1000}oh365userfinder\.py.{0,1000}/ nocase ascii wide
        // Description: Oh365UserFinder is used for identifying valid o365 accounts and domains without the risk of account lockouts. The tool parses responses to identify the IfExistsResult flag is null or not. and responds appropriately if the user is valid. The tool will attempt to identify false positives based on response. and either automatically create a waiting period to allow the throttling value to reset. or warn the user to increase timeouts between attempts.
        // Reference: https://github.com/dievus/Oh365UserFinder
        $string4 = /.{0,1000}Oh365UserFinder\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
