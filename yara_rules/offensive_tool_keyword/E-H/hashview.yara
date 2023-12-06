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
        $string1 = /\shashview\.py/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string2 = /\shashview\-agent\s/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string3 = /\.\/hashview\// nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string4 = /\/hashview\.py/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string5 = /\\hashview\.py/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string6 = /DoNotUseThisPassword123\!/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string7 = /hashview.{0,1000}\@.{0,1000}localhost/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string8 = /hashview\/config\.conf/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string9 = /hashview\/hashview/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string10 = /hashview\-agent\..{0,1000}\.tgz/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string11 = /hashview\-agent\.py/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string12 = /rockyou\.txt\.gz/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string13 = /wordlists\/dynamic\-all\.txt/ nocase ascii wide
        // Description: A web front-end for password cracking and analytics
        // Reference: https://github.com/hashview/hashview
        $string14 = /wordlists\/rockyou\.txt\'/ nocase ascii wide

    condition:
        any of them
}
