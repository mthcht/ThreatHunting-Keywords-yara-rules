rule expose
{
    meta:
        description = "Detection patterns for the tool 'expose' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "expose"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string1 = /\s\/usr\/local\/bin\/expose/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string2 = /\/expose\/database\/expose\.db/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string3 = /\/expose\/raw\/master\/builds\/expose/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string4 = /\/src\/expose\sserve\s/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string5 = /beyondcode\/expose/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string6 = /docker\sbuild\s\-t\sexpose\s/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string7 = /docker\srun\sexpose\s/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string8 = /expose\sshare\shttp\:\/\// nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string9 = /exposeConfigPath\=\/src\/config\/expose\.php/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string10 = /\'host\'\s\=\>\s\'sharedwithexpose\.com\'/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string11 = /http\:\/\/127\.0\.0\.1\:4040\/api\/logs\// nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string12 = /https\:\/\/expose\.dev\/api\/servers/ nocase ascii wide
        // Description: tunneling service - written in pure PHP
        // Reference: https://github.com/beyondcode/expose
        $string13 = /https\:\/\/expose\.dev\/register/ nocase ascii wide

    condition:
        any of them
}
