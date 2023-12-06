rule BesoToken
{
    meta:
        description = "Detection patterns for the tool 'BesoToken' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BesoToken"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string1 = /\.exe\sexec\s.{0,1000}\scmd\sinteractive/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string2 = /\/BesoToken\.cpp/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string3 = /\/BesoToken\.exe/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string4 = /\/BesoToken\.git/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string5 = /\[\+\]\sOpened\sProcess\sToken\sSucessufully\!/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string6 = /\\BesoToken\.cpp/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string7 = /\\BesoToken\.exe/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string8 = /\\BesoToken\.vcxproj/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string9 = /55A48A19\-1A5C\-4E0D\-A46A\-5DB04C1D8B03/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string10 = /BesoToken\.exe\slist/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string11 = /BesoToken\-master/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string12 = /OmriBaso\/BesoToken/ nocase ascii wide

    condition:
        any of them
}
