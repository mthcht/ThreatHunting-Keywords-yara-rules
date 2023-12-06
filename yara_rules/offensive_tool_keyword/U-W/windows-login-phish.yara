rule windows_login_phish
{
    meta:
        description = "Detection patterns for the tool 'windows-login-phish' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "windows-login-phish"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Login Phishing page This is a windows maching login page designed using HTML CSS and JS. This can be used for red teaming or cybersecurity awareness related purposes
        // Reference: https://github.com/CipherKill/windows-login-phish
        $string1 = /\/windows\-login\-phish/ nocase ascii wide
        // Description: Windows Login Phishing page This is a windows maching login page designed using HTML CSS and JS. This can be used for red teaming or cybersecurity awareness related purposes
        // Reference: https://github.com/CipherKill/windows-login-phish
        $string2 = /AttackerSetup\(windows\)\.exe/ nocase ascii wide
        // Description: Windows Login Phishing page This is a windows maching login page designed using HTML CSS and JS. This can be used for red teaming or cybersecurity awareness related purposes
        // Reference: https://github.com/CipherKill/windows-login-phish
        $string3 = /AttackerSetup\.py/ nocase ascii wide
        // Description: Windows Login Phishing page This is a windows maching login page designed using HTML CSS and JS. This can be used for red teaming or cybersecurity awareness related purposes
        // Reference: https://github.com/CipherKill/windows-login-phish
        $string4 = /AttackerSetup4linux/ nocase ascii wide

    condition:
        any of them
}
