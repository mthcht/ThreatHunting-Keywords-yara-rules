rule smtp_user_enum
{
    meta:
        description = "Detection patterns for the tool 'smtp-user-enum' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smtp-user-enum"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN - VRFY or RCPT TO.
        // Reference: https://pentestmonkey.net/tools/user-enumeration/smtp-user-enum
        $string1 = /\/smtp\-user\-enum/ nocase ascii wide
        // Description: Username guessing tool primarily for use against the default Solaris SMTP service. Can use either EXPN - VRFY or RCPT TO.
        // Reference: https://pentestmonkey.net/tools/user-enumeration/smtp-user-enum
        $string2 = /smtp\-user\-enum/ nocase ascii wide

    condition:
        any of them
}
