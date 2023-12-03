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
        $string1 = /.{0,1000}\sacltoolkit.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string2 = /.{0,1000}\sgive\-dcsync.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string3 = /.{0,1000}\sgive\-genericall\s.{0,1000}\s\-target\-sid\s.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string4 = /.{0,1000}\sset\-objectowner\s.{0,1000}\s\-target\-sid\s.{0,1000}\s\-owner\-sid\s.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string5 = /.{0,1000}\/acltoolkit.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string6 = /.{0,1000}\/add_groupmember\.py.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string7 = /.{0,1000}acltoolkit\s.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string8 = /.{0,1000}acltoolkit\.git.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string9 = /.{0,1000}acltoolkit\-ad.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string10 = /.{0,1000}acltoolkit\-main.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string11 = /.{0,1000}give_dcsync\.py.{0,1000}/ nocase ascii wide
        // Description: acltoolkit is an ACL abuse swiss-army knife. It implements multiple ACL abuses
        // Reference: https://github.com/zblurx/acltoolkit
        $string12 = /.{0,1000}set_logon_script\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
