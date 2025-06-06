rule chromepass
{
    meta:
        description = "Detection patterns for the tool 'chromepass' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "chromepass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string1 = ">ChromePass<" nocase ascii wide
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string2 = "490139a7800992202ca46d3a69882b476014126fc3ed4143c184bcd7f76a5761" nocase ascii wide
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string3 = "744e50af5566fa5ab70d4db70d35b3b89d75018e00b6b1e8e6280030482353bc" nocase ascii wide
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string4 = "Chrome Password Recovery" nocase ascii wide
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string5 = "Chrome Passwords List!" nocase ascii wide
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string6 = /chromepass\.exe/ nocase ascii wide
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string7 = /chromepass\.zip/ nocase ascii wide
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string8 = "Load the passwords from another Windows user or external drive" nocase ascii wide
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string9 = "Load the passwords of the current logged-on user" nocase ascii wide

    condition:
        any of them
}
