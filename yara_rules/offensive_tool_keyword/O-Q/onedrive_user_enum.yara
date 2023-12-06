rule onedrive_user_enum
{
    meta:
        description = "Detection patterns for the tool 'onedrive_user_enum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "onedrive_user_enum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string1 = /\/onedrive_user_enum/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string2 = /\-my\.sharepoint\.com\/personal\/Fakeuser/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string3 = /\-my\.sharepoint\.com\/personal\/TESTUSER_/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string4 = /OneDrive\sEnumerator/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string5 = /onedrive_enum\.py/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string6 = /onedrive_user_enum\.git/ nocase ascii wide

    condition:
        any of them
}
