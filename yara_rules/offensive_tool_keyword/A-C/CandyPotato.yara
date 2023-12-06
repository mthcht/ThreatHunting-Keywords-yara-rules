rule CandyPotato
{
    meta:
        description = "Detection patterns for the tool 'CandyPotato' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "CandyPotato"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CandyPotato - Pure C++ weaponized fully automated implementation of RottenPotatoNG. This tool has been made on top of the original JuicyPotato with the main focus on improving and adding some functionalities which was lacking
        // Reference: https://github.com/klezVirus/CandyPotato
        $string1 = /\/CandyPotato\.cpp/ nocase ascii wide
        // Description: CandyPotato - Pure C++ weaponized fully automated implementation of RottenPotatoNG. This tool has been made on top of the original JuicyPotato with the main focus on improving and adding some functionalities which was lacking
        // Reference: https://github.com/klezVirus/CandyPotato
        $string2 = /\/CandyPotato\.sdf/ nocase ascii wide
        // Description: CandyPotato - Pure C++ weaponized fully automated implementation of RottenPotatoNG. This tool has been made on top of the original JuicyPotato with the main focus on improving and adding some functionalities which was lacking
        // Reference: https://github.com/klezVirus/CandyPotato
        $string3 = /\/CandyPotato\.sln/ nocase ascii wide
        // Description: CandyPotato - Pure C++ weaponized fully automated implementation of RottenPotatoNG. This tool has been made on top of the original JuicyPotato with the main focus on improving and adding some functionalities which was lacking
        // Reference: https://github.com/klezVirus/CandyPotato
        $string4 = /\/CandyPotato\.vcxproj/ nocase ascii wide
        // Description: CandyPotato - Pure C++ weaponized fully automated implementation of RottenPotatoNG. This tool has been made on top of the original JuicyPotato with the main focus on improving and adding some functionalities which was lacking
        // Reference: https://github.com/klezVirus/CandyPotato
        $string5 = /\/klezVirus\/CandyPotato/ nocase ascii wide
        // Description: CandyPotato - Pure C++ weaponized fully automated implementation of RottenPotatoNG. This tool has been made on top of the original JuicyPotato with the main focus on improving and adding some functionalities which was lacking
        // Reference: https://github.com/klezVirus/CandyPotato
        $string6 = /CandyPotato\.exe\s/ nocase ascii wide

    condition:
        any of them
}
