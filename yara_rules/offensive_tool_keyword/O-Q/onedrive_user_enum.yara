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
        $string1 = /.{0,1000}\/onedrive_user_enum.{0,1000}/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string2 = /.{0,1000}\-my\.sharepoint\.com\/personal\/Fakeuser.{0,1000}/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string3 = /.{0,1000}\-my\.sharepoint\.com\/personal\/TESTUSER_.{0,1000}/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string4 = /.{0,1000}OneDrive\sEnumerator.{0,1000}/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string5 = /.{0,1000}onedrive_enum\.py.{0,1000}/ nocase ascii wide
        // Description: enumerate valid onedrive users
        // Reference: https://github.com/nyxgeek/onedrive_user_enum
        $string6 = /.{0,1000}onedrive_user_enum\.git.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
