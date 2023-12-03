rule passwordfox
{
    meta:
        description = "Detection patterns for the tool 'passwordfox' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passwordfox"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PasswordFox is a small password recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox Web browser. By default. PasswordFox displays the passwords stored in your current profile. but you can easily select to watch the passwords of any other Firefox profile. For each password entry. the following information is displayed: Record Index. Web Site. User Name. Password. User Name Field. Password Field. and the Signons filename.
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string1 = /.{0,1000}passwordfox\.exe.{0,1000}/ nocase ascii wide
        // Description: PasswordFox is a small password recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox Web browser. By default. PasswordFox displays the passwords stored in your current profile. but you can easily select to watch the passwords of any other Firefox profile. For each password entry. the following information is displayed: Record Index. Web Site. User Name. Password. User Name Field. Password Field. and the Signons filename.
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string2 = /.{0,1000}passwordfox\.zip.{0,1000}/ nocase ascii wide
        // Description: PasswordFox is a small password recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox Web browser. By default. PasswordFox displays the passwords stored in your current profile. but you can easily select to watch the passwords of any other Firefox profile. For each password entry. the following information is displayed: Record Index. Web Site. User Name. Password. User Name Field. Password Field. and the Signons filename.
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string3 = /.{0,1000}passwordfox\-x64\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
