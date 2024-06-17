rule browser_lol
{
    meta:
        description = "Detection patterns for the tool 'browser.lol' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "browser.lol"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Virtual Browser - Safely visit blocked or risky websites - can be used to bypass network restrictions within a corporate environment
        // Reference: https://browser.lol
        $string1 = /\&browser\=tor\&api\=false/ nocase ascii wide
        // Description: Virtual Browser - Safely visit blocked or risky websites - can be used to bypass network restrictions within a corporate environment
        // Reference: https://browser.lol
        $string2 = /\.srv\.browser\.lol/ nocase ascii wide
        // Description: Virtual Browser - Safely visit blocked or risky websites - can be used to bypass network restrictions within a corporate environment
        // Reference: https://browser.lol
        $string3 = /browser\.lol\/create/ nocase ascii wide
        // Description: Virtual Browser - Safely visit blocked or risky websites - can be used to bypass network restrictions within a corporate environment
        // Reference: https://browser.lol
        $string4 = /https\:\/\/browser\.lol\/vnc\?server\=/ nocase ascii wide

    condition:
        any of them
}
