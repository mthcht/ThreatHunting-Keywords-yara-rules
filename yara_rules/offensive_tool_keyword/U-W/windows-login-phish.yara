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
        $string1 = /.{0,1000}\/windows\-login\-phish.{0,1000}/ nocase ascii wide
        // Description: Windows Login Phishing page This is a windows maching login page designed using HTML CSS and JS. This can be used for red teaming or cybersecurity awareness related purposes
        // Reference: https://github.com/CipherKill/windows-login-phish
        $string2 = /.{0,1000}AttackerSetup\(windows\)\.exe.{0,1000}/ nocase ascii wide
        // Description: Windows Login Phishing page This is a windows maching login page designed using HTML CSS and JS. This can be used for red teaming or cybersecurity awareness related purposes
        // Reference: https://github.com/CipherKill/windows-login-phish
        $string3 = /.{0,1000}AttackerSetup\.py.{0,1000}/ nocase ascii wide
        // Description: Windows Login Phishing page This is a windows maching login page designed using HTML CSS and JS. This can be used for red teaming or cybersecurity awareness related purposes
        // Reference: https://github.com/CipherKill/windows-login-phish
        $string4 = /.{0,1000}AttackerSetup4linux.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
