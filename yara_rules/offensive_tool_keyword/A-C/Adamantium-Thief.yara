rule Adamantium_Thief
{
    meta:
        description = "Detection patterns for the tool 'Adamantium-Thief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adamantium-Thief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string1 = /\.exe\sBOOKMARKS/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string2 = /\.exe\sCOOKIES/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string3 = /\.exe\sCREDIT_CARDS/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string4 = /\/Adamantium\-Thief\.git/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string5 = /\/Stealer\.exe/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string6 = /\/Stealer\.sln/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string7 = /\\Stealer\.exe/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string8 = /\\Stealer\.sln/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string9 = /\\Stealer\\modules\\Passwords\.cs/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string10 = /\\Stealer\\Stealer\\modules\\/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string11 = /Adamantium\-Thief\-master/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string12 = /Coded\sby\sLimerBoy\s\<3/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string13 = /E6104BC9\-FEA9\-4EE9\-B919\-28156C1F2EDE/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string14 = /LimerBoy\/Adamantium\-Thief/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string15 = /Please\sselect\scommand\s\[PASSWORDS\/HISTORY\/COOKIES\/AUTOFILL\/CREDIT_CARDS\/BOOKMARKS\]/ nocase ascii wide
        // Description: Decrypt chromium based browsers passwords - cookies - credit cards - history - bookmarks and autofill.
        // Reference: https://github.com/LimerBoy/Adamantium-Thief
        $string16 = /Stealer\.exe\s/ nocase ascii wide

    condition:
        any of them
}
