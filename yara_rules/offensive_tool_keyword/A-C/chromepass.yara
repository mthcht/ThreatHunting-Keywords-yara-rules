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
        $string1 = /chromepass\.exe/ nocase ascii wide
        // Description: ChromePass is a small password recovery tool for Windows that allows you to view the user names and passwords stored by Google Chrome Web browser. For each password entry. the following information is displayed: Origin URL. Action URL. User Name Field. Password Field. User Name. Password. and Created Time. It allows you to get the passwords from your current running system. or from a user profile stored on external drive.
        // Reference: https://www.nirsoft.net/utils/chromepass.html
        $string2 = /chromepass\.zip/ nocase ascii wide

    condition:
        any of them
}
