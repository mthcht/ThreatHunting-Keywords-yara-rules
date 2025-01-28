rule CursedChrome
{
    meta:
        description = "Detection patterns for the tool 'CursedChrome' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CursedChrome"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string1 = /\/CursedChrome\.git/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string2 = /\/extension_injection\.sh/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string3 = /\/redirect\-hack\.html\?id\=/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string4 = /127\.0\.0\.1\:8118/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string5 = "A new browser has connected to us via WebSocket!" nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string6 = /bash\sextension_injection\.sh/
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string7 = "const subscription_id = `TOPROXY_" nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string8 = /COPY\sanyproxy\/\s\.\/anyproxy\//
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string9 = "CursedChrome API server is now listening on port" nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string10 = "CursedChrome WebSocket server is now running on port" nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string11 = /CursedChrome\-master\.zip/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string12 = "DATABASE_PASSWORD: cursedchrome" nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string13 = "DATABASE_USER: cursedchrome" nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string14 = /docker\simages\s\|\sgrep\scursed/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string15 = /docker\sps\s\-a\s\|\sgrep\scursed/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string16 = "docker-compose up cursedchrome" nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string17 = "http://localhost:8118" nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string18 = /logit\(\`New\ssubscriber\:\sTOBROWSER__/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string19 = "mandatoryprogrammer/CursedChrome" nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string20 = /new\sWebSocket\(\\"ws\:\/\/127\.0\.0\.1\:4343\\"\)/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string21 = /publisher\.publish\(\`TOBROWSER_/ nocase ascii wide
        // Description: Chrome-extension implant that turns victim Chrome browsers into fully-functional HTTP proxies allowing you to browse sites as your victims
        // Reference: https://github.com/mandatoryprogrammer/CursedChrome
        $string22 = /Wat\,\sthis\sshouldn\'t\shappen\?\sOrphaned\smessage\s\(somebody\smight\sbe\sprobing\syou\!\)\:/ nocase ascii wide

    condition:
        any of them
}
