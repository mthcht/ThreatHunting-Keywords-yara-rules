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
        $string1 = /.{0,1000}\/disctopia\.py.{0,1000}/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string2 = /.{0,1000}\/disctopia\-c2.{0,1000}/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string3 = /.{0,1000}\/distopia\-test.{0,1000}/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string4 = /.{0,1000}Disctopia\sBackdoor.{0,1000}/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string5 = /.{0,1000}disctopia\-c2\.git.{0,1000}/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string6 = /.{0,1000}disctopia\-c2\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string7 = /.{0,1000}keylogger\.py.{0,1000}/ nocase ascii wide
        // Description: Windows Remote Administration Tool that uses Discord Telegram and GitHub as C2s
        // Reference: https://github.com/3ct0s/disctopia-c2
        $string8 = /.{0,1000}sandboxevasion\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
