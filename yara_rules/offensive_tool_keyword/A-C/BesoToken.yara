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
        $string1 = /.{0,1000}\.exe\sexec\s.{0,1000}\scmd\sinteractive.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string2 = /.{0,1000}\/BesoToken\.cpp.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string3 = /.{0,1000}\/BesoToken\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string4 = /.{0,1000}\/BesoToken\.git.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string5 = /.{0,1000}\[\+\]\sOpened\sProcess\sToken\sSucessufully\!.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string6 = /.{0,1000}\\BesoToken\.cpp.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string7 = /.{0,1000}\\BesoToken\.exe.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string8 = /.{0,1000}\\BesoToken\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string9 = /.{0,1000}55A48A19\-1A5C\-4E0D\-A46A\-5DB04C1D8B03.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string10 = /.{0,1000}BesoToken\.exe\slist.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string11 = /.{0,1000}BesoToken\-master.{0,1000}/ nocase ascii wide
        // Description: A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).
        // Reference: https://github.com/OmriBaso/BesoToken
        $string12 = /.{0,1000}OmriBaso\/BesoToken.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
