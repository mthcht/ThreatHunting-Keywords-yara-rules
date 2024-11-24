rule passwordfox
{
    meta:
        description = "Detection patterns for the tool 'passwordfox' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "passwordfox"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string1 = /\/utils\/passwordfox\.html/ nocase ascii wide
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string2 = ">PasswordFox<" nocase ascii wide
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string3 = ">Password-Recovery For Firefox<" nocase ascii wide
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string4 = "22c75c356f7e3a118f3fb98fe16c5c9232e3834e631ea1bb2af6a923f57b7b0b" nocase ascii wide
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string5 = "faca9e856c369b63d6698c74b1d59b062a9a8d9fe84b8f753c299c9961026395" nocase ascii wide
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string6 = /passwordfox\.exe/ nocase ascii wide
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string7 = /passwordfox\.zip/ nocase ascii wide
        // Description: recovery tool that allows you to view the user names and passwords stored by Mozilla Firefox
        // Reference: https://www.nirsoft.net/utils/passwordfox.html
        $string8 = /passwordfox\-x64\.zip/ nocase ascii wide

    condition:
        any of them
}
