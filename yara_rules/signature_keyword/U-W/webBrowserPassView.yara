rule webBrowserPassView
{
    meta:
        description = "Detection patterns for the tool 'webBrowserPassView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webBrowserPassView"
        rule_category = "signature_keyword"

    strings:
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string1 = /HackTool\.Win32\.NirsoftPT\.SM/ nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string2 = /PSWTool\.Win32\.PassView/ nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string3 = "PUA:Win32/PassShow" nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string4 = "Riskware/WebBrowserPassView" nocase ascii wide

    condition:
        any of them
}
