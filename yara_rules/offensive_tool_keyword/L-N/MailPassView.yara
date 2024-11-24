rule MailPassView
{
    meta:
        description = "Detection patterns for the tool 'MailPassView' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "MailPassView"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details for multiple email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string1 = /\/mailpv\.exe/ nocase ascii wide
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details for multiple email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string2 = /\/utils\/mailpv\.html/ nocase ascii wide
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details for multiple email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string3 = /\\mailpv\.exe/ nocase ascii wide
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details for multiple email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string4 = "18e9b39ab7c27ea80c6b76fc04881a5348de491ab22abe65a6bdb7254e23d5d1" nocase ascii wide
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details for multiple email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string5 = "5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd" nocase ascii wide
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details for multiple email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string6 = "5be325905df8aab7089ab2348d89343f55a2f88dadd75de8f382e8fa026451bd" nocase ascii wide
        // Description: Mail PassView is a small password-recovery tool that reveals the passwords and other account details for multiple email clients
        // Reference: https://www.nirsoft.net/utils/mailpv.html
        $string7 = "Email  Password-Recovery" nocase ascii wide

    condition:
        any of them
}
