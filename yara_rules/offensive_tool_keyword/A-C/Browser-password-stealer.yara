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
        $string1 = /.{0,1000}\schromium_based_browsers\.py.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string2 = /.{0,1000}\/chromium_based_browsers\.py.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string3 = /.{0,1000}\\chromium_based_browsers\.py.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string4 = /.{0,1000}Browser\-password\-stealer\.git.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string5 = /.{0,1000}Browser\-password\-stealer\-master.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string6 = /.{0,1000}google\-chrome\/cookies\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string7 = /.{0,1000}google\-chrome\/credit_cards\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string8 = /.{0,1000}google\-chrome\/history\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string9 = /.{0,1000}google\-chrome\/login_data\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string10 = /.{0,1000}google\-chrome\\cookies\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string11 = /.{0,1000}google\-chrome\\credit_cards\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string12 = /.{0,1000}google\-chrome\\history\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string13 = /.{0,1000}google\-chrome\\login_data\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string14 = /.{0,1000}henry\-richard7\/Browser\-password\-stealer.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string15 = /.{0,1000}microsoft\-edge\/cookies\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string16 = /.{0,1000}microsoft\-edge\/credit_cards\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string17 = /.{0,1000}microsoft\-edge\/history\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string18 = /.{0,1000}microsoft\-edge\/login_data\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string19 = /.{0,1000}microsoft\-edge\\cookies\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string20 = /.{0,1000}microsoft\-edge\\credit_cards\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string21 = /.{0,1000}microsoft\-edge\\history\.txt.{0,1000}/ nocase ascii wide
        // Description: This python program gets all the saved passwords + credit cards and bookmarks from chromium based browsers supports chromium 80 and above!
        // Reference: https://github.com/henry-richard7/Browser-password-stealer
        $string22 = /.{0,1000}microsoft\-edge\\login_data\.txt.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
