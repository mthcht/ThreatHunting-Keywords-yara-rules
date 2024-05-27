rule Proxifier
{
    meta:
        description = "Detection patterns for the tool 'Proxifier' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Proxifier"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string1 = /\sstop\sProxifierDrv/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string2 = /\/Proxifier\.app\/Contents\/MacOS\/Proxifier/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string3 = /\/Proxifier\.exe/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string4 = /\/Proxifier\/Proxifier\.app\// nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string5 = /\/ProxifierPE\.zip/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string6 = /\/ProxifierSetup\.exe/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string7 = /\\AppData\\Local\\Temp\\.{0,1000}\\Proxifier\sPE\\/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string8 = /\\AppData\\Local\\Temp\\Proxifier\sPE\\/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string9 = /\\Proxifier\sService\sManager\.lnk/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string10 = /\\Proxifier\.exe/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string11 = /\\Proxifier\.lnk/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string12 = /\\ProxifierDrv\.sys/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string13 = /\\ProxifierPE\.zip/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string14 = /\\ProxifierSetup\.exe/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string15 = /\\ProxifierSetup\.tmp/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string16 = /\\ProxifierShellExt\.dll/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string17 = /\\ProxyChecker\.exe/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string18 = /\\SOFTWARE\\WOW6432Node\\Microsoft\\Tracing\\Proxifier_/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string19 = /\\Start\sMenu\\Programs\\Proxifier/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string20 = /\>Proxifier\sSetup\</ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string21 = /com\.initex\.proxifier\.v3\.macos/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string22 = /http\:\/\/www\.proxifier\.com\/distr\/last_versions\/ProxifierMac/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string23 = /http\:\/\/www\.proxifier\.com\/distr\/last_versions\/ProxifierPortable/ nocase ascii wide
        // Description: allows to proxy connections for programs
        // Reference: https://www.proxifier.com/download/
        $string24 = /Program\sFiles\s\(x86\)\\Proxifier/ nocase ascii wide

    condition:
        any of them
}
