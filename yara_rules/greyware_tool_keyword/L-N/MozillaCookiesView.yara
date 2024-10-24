rule MozillaCookiesView
{
    meta:
        description = "Detection patterns for the tool 'MozillaCookiesView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MozillaCookiesView"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string1 = /\/mzcv\.exe/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string2 = /\/mzcv\-x64\.zip/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string3 = /\\mzcv\.exe/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string4 = /\\mzcv\-x64\.zip/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string5 = /\>MZCookiesView\</ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string6 = /0fbcaa65ada37326741259d2ebc96d52e61d38cd6c28823194f2ffb4bf906ebe/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string7 = /cace36a7ea185c8a675356f6e3eeb5b1d466666f7853aa9813df486c5178cbdf/ nocase ascii wide
        // Description: nirsoft utility that displays the details of all cookies stored inside the cookies file (cookies.txt or cookies.sqlite) - abused by threat actors
        // Reference: https://www.nirsoft.net/utils/mzcv.html
        $string8 = /MZCookiesView.{0,1000}cookies\.sqlite/ nocase ascii wide

    condition:
        any of them
}
