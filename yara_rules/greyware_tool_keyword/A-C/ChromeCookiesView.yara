rule ChromeCookiesView
{
    meta:
        description = "Detection patterns for the tool 'ChromeCookiesView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ChromeCookiesView"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: displays the list of all cookies stored by Google Chrome Web browser - abused by attackers
        // Reference: https://www.nirsoft.net/utils/chrome_cookies_view.html
        $string1 = /\\ChromeCookiesView\.cfg/ nocase ascii wide
        // Description: displays the list of all cookies stored by Google Chrome Web browser - abused by attackers
        // Reference: https://www.nirsoft.net/utils/chrome_cookies_view.html
        $string2 = "5b992399231bc699bda60ec893e9c5af0ccded956ebfe5d02eaa41cb91fea9c8" nocase ascii wide
        // Description: displays the list of all cookies stored by Google Chrome Web browser - abused by attackers
        // Reference: https://www.nirsoft.net/utils/chrome_cookies_view.html
        $string3 = /ChromeCookiesView\.exe/ nocase ascii wide
        // Description: displays the list of all cookies stored by Google Chrome Web browser - abused by attackers
        // Reference: https://www.nirsoft.net/utils/chrome_cookies_view.html
        $string4 = /chromecookiesview\.zip/ nocase ascii wide
        // Description: displays the list of all cookies stored by Google Chrome Web browser - abused by attackers
        // Reference: https://www.nirsoft.net/utils/chrome_cookies_view.html
        $string5 = /chromecookiesview\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}
