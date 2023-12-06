rule Browser_password_stealer
{
    meta:
        description = "Detection patterns for the tool 'Browser-password-stealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Browser-password-stealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string1 = /\schromium_based_browsers\.py/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string2 = /\/chromium_based_browsers\.py/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string3 = /\\chromium_based_browsers\.py/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string4 = /Browser\-password\-stealer\.git/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string5 = /Browser\-password\-stealer\-master/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string6 = /google\-chrome\/cookies\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string7 = /google\-chrome\/credit_cards\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string8 = /google\-chrome\/history\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string9 = /google\-chrome\/login_data\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string10 = /google\-chrome\\cookies\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string11 = /google\-chrome\\credit_cards\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string12 = /google\-chrome\\history\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string13 = /google\-chrome\\login_data\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string14 = /henry\-richard7\/Browser\-password\-stealer/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string15 = /microsoft\-edge\/cookies\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string16 = /microsoft\-edge\/credit_cards\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string17 = /microsoft\-edge\/history\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string18 = /microsoft\-edge\/login_data\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string19 = /microsoft\-edge\\cookies\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string20 = /microsoft\-edge\\credit_cards\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string21 = /microsoft\-edge\\history\.txt/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string22 = /microsoft\-edge\\login_data\.txt/ nocase ascii wide

    condition:
        any of them
}
