rule TokenUniverse
{
    meta:
        description = "Detection patterns for the tool 'TokenUniverse' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TokenUniverse"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string1 = /\sTokenUniverse\.zip/ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string2 = /\/TokenUniverse\.git/ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string3 = /\/TokenUniverse\.zip/ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string4 = /\\TokenUniverse\.zip/ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string5 = /\\TokenUniverse\\TokenUniverse\./ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string6 = /diversenok\/TokenUniverse/ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string7 = /TokenUniverse\.dproj/ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string8 = /TokenUniverse\.exe/ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string9 = /TokenUniverse\-master\.zip/ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string10 = /TokenUniverse\-x64\.zip/ nocase ascii wide
        // Description: An advanced tool for working with access tokens and Windows security policy.
        // Reference: https://github.com/diversenok/TokenUniverse
        $string11 = /TokenUniverse\-x86\.zip/ nocase ascii wide

    condition:
        any of them
}
