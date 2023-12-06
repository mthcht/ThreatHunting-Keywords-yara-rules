rule acltoolkit
{
    meta:
        description = "Detection patterns for the tool 'acltoolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "acltoolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string1 = /\sacltoolkit/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string2 = /\sgive\-dcsync/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string3 = /\sgive\-genericall\s.{0,1000}\s\-target\-sid\s/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string4 = /\sset\-objectowner\s.{0,1000}\s\-target\-sid\s.{0,1000}\s\-owner\-sid\s/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string5 = /\/acltoolkit/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string6 = /\/add_groupmember\.py/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string7 = /acltoolkit\s/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string8 = /acltoolkit\.git/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string9 = /acltoolkit\-ad/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string10 = /acltoolkit\-main/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string11 = /give_dcsync\.py/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string12 = /set_logon_script\.py/ nocase ascii wide

    condition:
        any of them
}
