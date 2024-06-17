rule PWA_Phishing
{
    meta:
        description = "Detection patterns for the tool 'PWA-Phishing' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PWA-Phishing"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string1 = /\/mrd0x\.html/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string2 = /\/PWA\-Phishing\.git/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string3 = /\\PWA\-Phishing/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string4 = /18c54c69f41d0b7e5928c34e1e9350ed99ecd0278ea37df11a429018ca3d05ed/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string5 = /3b1e2b01bfa6ad0deefa3bf8e7a81e9fc295e56b8f087ef402d9a06e42ec3b95/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string6 = /95b9a6d12b978a6c1bbd6a33369e39008e7d64544d50c98c9c3f2b93a9466e79/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string7 = /bfa9dc4c4b911b6777cb98d17a82b28531c26600698699cbe658749684818f28/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string8 = /fopen\(\'credentials\.txt\'/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string9 = /https\:\/\/mrd0x\.com\/progressive\-web\-apps\-pwa\-phishing/ nocase ascii wide
        // Description: Phishing with Progressive Web Apps and UI manipulation
        // Reference: https://github.com/mrd0x/PWA-Phishing
        $string10 = /mrd0x\/PWA\-Phishing/ nocase ascii wide

    condition:
        any of them
}
