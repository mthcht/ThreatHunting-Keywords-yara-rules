rule disctopia_c2
{
    meta:
        description = "Detection patterns for the tool 'disctopia-c2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "disctopia-c2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string1 = /\/disctopia\.py/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string2 = /\/disctopia\-c2/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string3 = /\/distopia\-test/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string4 = /Disctopia\sBackdoor/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string5 = /disctopia\-c2\.git/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string6 = /disctopia\-c2\-main\.zip/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string7 = /keylogger\.py/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string8 = /sandboxevasion\.py/ nocase ascii wide

    condition:
        any of them
}
