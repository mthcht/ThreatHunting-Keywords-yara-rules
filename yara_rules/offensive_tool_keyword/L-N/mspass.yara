rule mspass
{
    meta:
        description = "Detection patterns for the tool 'mspass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mspass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MessenPass can only be used to recover the passwords for the current logged-on user on your local computer. and it only works if you chose the remember your password in one of the above programs. You cannot use this utility for grabbing the passwords of other users.
        // Reference: https://www.nirsoft.net/utils/mspass.html
        $string1 = /.{0,1000}mspass\.exe.{0,1000}/ nocase ascii wide
        // Description: MessenPass can only be used to recover the passwords for the current logged-on user on your local computer. and it only works if you chose the remember your password in one of the above programs. You cannot use this utility for grabbing the passwords of other users.
        // Reference: https://www.nirsoft.net/utils/mspass.html
        $string2 = /.{0,1000}mspass\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
