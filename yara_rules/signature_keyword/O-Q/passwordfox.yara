rule passwordfox
{
    meta:
        description = "Detection patterns for the tool 'passwordfox' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passwordfox"
        rule_category = "signature_keyword"

    strings:
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string1 = /Nirsoft\sPasswordFox\s\(PUA\)/ nocase ascii wide
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string2 = /PSWTool\.PasswordFox\./ nocase ascii wide
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string3 = /PSWTool\.Win64\.FirePass\./ nocase ascii wide

    condition:
        any of them
}
