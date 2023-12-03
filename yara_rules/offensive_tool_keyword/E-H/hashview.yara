rule hashview
{
    meta:
        description = "Detection patterns for the tool 'hashview' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hashview"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string1 = /.{0,1000}\shashview\.py.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string2 = /.{0,1000}\shashview\-agent\s.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string3 = /.{0,1000}\.\/hashview\/.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string4 = /.{0,1000}\/hashview\.py.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string5 = /.{0,1000}\\hashview\.py.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string6 = /.{0,1000}DoNotUseThisPassword123\!.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string7 = /.{0,1000}hashview.{0,1000}\@.{0,1000}localhost.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string8 = /.{0,1000}hashview\/config\.conf.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string9 = /.{0,1000}hashview\/hashview.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string10 = /.{0,1000}hashview\-agent\..{0,1000}\.tgz.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string11 = /.{0,1000}hashview\-agent\.py.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string12 = /.{0,1000}rockyou\.txt\.gz.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string13 = /.{0,1000}wordlists\/dynamic\-all\.txt.{0,1000}/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string14 = /.{0,1000}wordlists\/rockyou\.txt\'.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
