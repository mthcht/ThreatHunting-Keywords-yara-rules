rule Sandman
{
    meta:
        description = "Detection patterns for the tool 'Sandman' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sandman"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string1 = /\ssandman_server\.py/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string2 = /\#\sIf\sgot\sa\smalicious\spacket\s\-\sActivate\sthe\sbackdoor\!/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string3 = /\/Sandman\.exe/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string4 = /\/sandman_server\.py/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string5 = /\/SandmanBackdoorTimeProvider\.dll/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string6 = /\/Sandman\-master\.zip/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string7 = /\[\s\+\s\]\sGot\sa\spacket\sfrom\sthe\sbackdoor\!/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string8 = /\\Sandman\.exe/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string9 = /\\sandman_server\.py/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string10 = /\\SandmanBackdoorTimeProvider\.dll/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string11 = /\\Sandman\-master\.zip/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string12 = /\>SandmanBackdoorTimeProvider\</ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string13 = /037efb13ec86af0dd0aa92bae0e8dbb3d50de958e8936dfeb2938ee3ea4a3136/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string14 = /037efb13ec86af0dd0aa92bae0e8dbb3d50de958e8936dfeb2938ee3ea4a3136/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string15 = /1bc73a13029b5677f070a991cec0ed90f3ebd70bcc0566a4724496eb71792dee/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string16 = /74f0a367e0af7a5885ece4682a8e1a07945893090ecf8c9677310954c7d9c479/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string17 = /B362EC25\-70BD\-4E6C\-9744\-173D20FDA392/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string18 = /E9F7C24C\-879D\-49F2\-B9BF\-2477DC28E2EE/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string19 = /f34befa3856ca7fedc2081903e35dff0eb86147aa6e163169355e46f8d5c3c98/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string20 = /Idov31\/Sandman/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string21 = /MALICIOUS_MAGIC\s\=\sb\"IDOV31\"/ nocase ascii wide
        // Description: Sandman is a NTP based backdoor for red team engagements in hardened networks.
        // Reference: https://github.com/Idov31/Sandman
        $string22 = /reg\sadd\s\"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient\\\"\s\/v\s.{0,1000}\.dll/ nocase ascii wide

    condition:
        any of them
}
