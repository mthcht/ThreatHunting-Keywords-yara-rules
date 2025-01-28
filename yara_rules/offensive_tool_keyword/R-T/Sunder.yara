rule Sunder
{
    meta:
        description = "Detection patterns for the tool 'Sunder' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Sunder"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string1 = /\/sunder\.exe/ nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string2 = /\[PRIVESC\]\sGiving\stoken\sfull\sprivileges\sfor\sPID/ nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string3 = /\[PRIVESC\]\sStealing\stoken\sfrom\sPID\s/ nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string4 = /\\sunder\.exe/ nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string5 = /\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\\\s\-Name\sVulnerableDriverBlocklistEnable\s0/ nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string6 = "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5" nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string7 = "5a958c89-6327-401c-a214-c89e54855b57" nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string8 = "643ad690-5c85-4b12-af42-2d31d11657a1" nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string9 = "c9d9c56c1eb6891ede852ccc96dc343afbd5057ab0451bc75ba7095203f0762a" nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string10 = "ColeHouston/Sunder" nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string11 = "d42270ec9fee729c30fd5b96918170c896436b04b863a82d578beff5fd980a6c" nocase ascii wide
        // Description: Windows rootkit designed to work with BYOVD exploits
        // Reference: https://github.com/ColeHouston/Sunder
        $string12 = /sc\screate\sdellserv\sbinPath\=C\:\\dbutil_2_3\.sys\stype\=kernel/ nocase ascii wide

    condition:
        any of them
}
