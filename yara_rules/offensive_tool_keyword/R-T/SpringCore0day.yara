rule SpringCore0day
{
    meta:
        description = "Detection patterns for the tool 'SpringCore0day' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpringCore0day"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SpringCore0day from share.vx-underground.org & some additional links
        // Reference: https://github.com/craig/SpringCore0day
        $string1 = /\/SpringCore0day/ nocase ascii wide
        // Description: SpringCore0day from share.vx-underground.org & some additional links
        // Reference: https://github.com/craig/SpringCore0day
        $string2 = /curl\s\-\-output\s.{0,1000}http.{0,1000}\/tomcatwar\.jsp\?/ nocase ascii wide
        // Description: SpringCore0day from share.vx-underground.org & some additional links
        // Reference: https://github.com/craig/SpringCore0day
        $string3 = /python3\s\.\/exp\.py\s\-\-url\shttp\:\/\// nocase ascii wide
        // Description: SpringCore0day from share.vx-underground.org & some additional links
        // Reference: https://github.com/craig/SpringCore0day
        $string4 = /vulfocus\/spring\-core\-rce\-/ nocase ascii wide

    condition:
        any of them
}
