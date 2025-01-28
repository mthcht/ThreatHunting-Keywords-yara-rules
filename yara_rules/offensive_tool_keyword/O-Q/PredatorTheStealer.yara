rule PredatorTheStealer
{
    meta:
        description = "Detection patterns for the tool 'PredatorTheStealer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PredatorTheStealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string1 = /\/c\sping\s127\.0\.0\.1\s\&\&\sdel\s\\\\/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string2 = /\/PredatorTheStealer\.git/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string3 = /\\PredatorTheStealer\sDll\./ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string4 = /\\PredatorTheStealer\./ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string5 = /\\Stealing\.cpp/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string6 = /\\tor\\hidden_service\./ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string7 = /\\tor\\onion_router\./ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string8 = "190DFAEB-0288-4043-BE0E-3273FA653B52" nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string9 = "30444d3f4f3bedc5d6aac36ad4deb9ce32d2ac91eb0b30e590f702b06825f372" nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string10 = "99383be21201b97e739e06f5c89a815cd4a296030985505f238862aecbbb7a77" nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string11 = /BTW\si\suse\sARCH\.\sA\s\-\sJeffrey\sEpstein\.\sR\s\-\sdidnt\.\sC\s\-\skill\.\sH\s\-\shimself/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string12 = "DC3E0E14-6342-41C9-BECC-3653BF533CCC" nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/PredatorTheStealer
        $string13 = "SecUser1/PredatorTheStealer" nocase ascii wide

    condition:
        any of them
}
