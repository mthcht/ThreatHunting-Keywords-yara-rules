rule PasswordHashesView
{
    meta:
        description = "Detection patterns for the tool 'PasswordHashesView' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PasswordHashesView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: displays the SHA1 hash and the NTLM hash of the login password for users currently logged into your system
        // Reference: https://www.nirsoft.net/alpha/passwordhashesview-x64.zip
        $string1 = ">PasswordHashesView<" nocase ascii wide
        // Description: displays the SHA1 hash and the NTLM hash of the login password for users currently logged into your system
        // Reference: https://www.nirsoft.net/alpha/passwordhashesview-x64.zip
        $string2 = /PasswordHashesView\.exe/ nocase ascii wide
        // Description: displays the SHA1 hash and the NTLM hash of the login password for users currently logged into your system
        // Reference: https://www.nirsoft.net/alpha/passwordhashesview-x64.zip
        $string3 = /passwordhashesview\.zip/ nocase ascii wide
        // Description: displays the SHA1 hash and the NTLM hash of the login password for users currently logged into your system
        // Reference: https://www.nirsoft.net/alpha/passwordhashesview-x64.zip
        $string4 = /passwordhashesview\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}
