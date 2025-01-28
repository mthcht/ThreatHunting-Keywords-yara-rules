rule m365_fatigue
{
    meta:
        description = "Detection patterns for the tool 'm365-fatigue' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "m365-fatigue"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: automates the authentication process for Microsoft 365 by using the device code flow and Selenium for automated login. It keeps bombing the user with MFA requests and stores the access_token once the MFA was approved.
        // Reference: https://github.com/0xB455/m365-fatigue
        $string1 = /\sm365\-fatigue\.py\s/ nocase ascii wide
        // Description: automates the authentication process for Microsoft 365 by using the device code flow and Selenium for automated login. It keeps bombing the user with MFA requests and stores the access_token once the MFA was approved.
        // Reference: https://github.com/0xB455/m365-fatigue
        $string2 = /\/m365\-fatigue\.git/ nocase ascii wide
        // Description: automates the authentication process for Microsoft 365 by using the device code flow and Selenium for automated login. It keeps bombing the user with MFA requests and stores the access_token once the MFA was approved.
        // Reference: https://github.com/0xB455/m365-fatigue
        $string3 = /\/m365\-fatigue\.py/ nocase ascii wide
        // Description: automates the authentication process for Microsoft 365 by using the device code flow and Selenium for automated login. It keeps bombing the user with MFA requests and stores the access_token once the MFA was approved.
        // Reference: https://github.com/0xB455/m365-fatigue
        $string4 = /\\m365\-fatigue\.py/ nocase ascii wide
        // Description: automates the authentication process for Microsoft 365 by using the device code flow and Selenium for automated login. It keeps bombing the user with MFA requests and stores the access_token once the MFA was approved.
        // Reference: https://github.com/0xB455/m365-fatigue
        $string5 = "0xB455/m365-fatigue" nocase ascii wide
        // Description: automates the authentication process for Microsoft 365 by using the device code flow and Selenium for automated login. It keeps bombing the user with MFA requests and stores the access_token once the MFA was approved.
        // Reference: https://github.com/0xB455/m365-fatigue
        $string6 = "d86bebcde6d5835cd2237d4e37df9858102002a4b9211aa3827e4bec0eca9897" nocase ascii wide

    condition:
        any of them
}
