rule CursedChrome
{
    meta:
        description = "Detection patterns for the tool 'CursedChrome' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CursedChrome"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string1 = /\/anyproxy\.log/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string2 = /\/work\/anyproxy\/bin\/anyproxy\-ca\s\-\-generate/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string3 = /anyproxy\s\-\-intercept\s\-\-ws\-intercept\s/ nocase ascii wide

    condition:
        any of them
}
