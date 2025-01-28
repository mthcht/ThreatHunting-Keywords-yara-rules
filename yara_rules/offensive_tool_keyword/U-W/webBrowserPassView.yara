rule webBrowserPassView
{
    meta:
        description = "Detection patterns for the tool 'webBrowserPassView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "webBrowserPassView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string1 = /\/web_browser_password\.html/ nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string2 = /\\WebBrowserPassView\.cfg/ nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string3 = /\\WebBrowserPassView\.chm/ nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string4 = /\\WebBrowserPassView_lng\.ini/ nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string5 = ">Web Browser Password Viewer<" nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string6 = ">WebBrowserPassView<" nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string7 = "72c3a786661ee9742cf1d0e3b99b89e976911ed87971695f08487cf42d7fc29d" nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string8 = "e7542c38e0b979f920fb88b59b25c3d6ae433ca145f7758938b322a71accecae" nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string9 = /f\:\\temp\\passwords\.html/ nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string10 = /WebBrowserPassView\.exe/ nocase ascii wide
        // Description: WebBrowserPassView is a password recovery tool that reveals the passwords stored by the following Web browsers: Internet Explorer (Version 4.0 - 11.0). Mozilla Firefox (All Versions). Google Chrome. Safari. and Opera. This tool can be used to recover your lost/forgotten password of any Website. including popular Web sites. like Facebook. Yahoo. Google. and GMail. as long as the password is stored by your Web Browser.
        // Reference: https://www.nirsoft.net/utils/web_browser_password.html
        $string11 = /WebBrowserPassView\.zip/ nocase ascii wide

    condition:
        any of them
}
