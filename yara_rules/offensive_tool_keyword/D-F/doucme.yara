rule doucme
{
    meta:
        description = "Detection patterns for the tool 'doucme' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "doucme"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string1 = /\"NSA0XF\$\"/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string2 = /\/DoUCMe\.git/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string3 = /\\doucme\.csproj/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string4 = /\\doucme\.exe/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string5 = /\\doucme\.sln/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string6 = /A11E7DAE\-21F2\-46A8\-991E\-D38DEBE1650F/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string7 = /All\sDone\!\sHack\sthe\splanet\!/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string8 = /Ben0xA\/DoUCMe/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string9 = /DoUCMe\-main\\/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string10 = /Enumerating\sAdministrators\sgroup\,\splease\swait/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string11 = /Enumerating\snew\suser\,\splease\swait/ nocase ascii wide
        // Description: leverages the NetUserAdd Win32 API to create a new computer account
        // Reference: https://github.com/Ben0xA/DoUCMe
        $string12 = /PASSWORD\s\=\s\"Letmein123\!/ nocase ascii wide

    condition:
        any of them
}
