rule Necro_Stealer
{
    meta:
        description = "Detection patterns for the tool 'Necro-Stealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Necro-Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/Necro-Stealer
        $string1 = /\/Necro\-Stealer\.git/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/Necro-Stealer
        $string2 = /\\Necro\-Stealer\-.{0,1000}\.zip/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/Necro-Stealer
        $string3 = /a568c8a8c28b7ceeee2f5eec82f94dd4fb0fc06175b2ee3043f863a68451ebbd/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/Necro-Stealer
        $string4 = /ac3107cf\-291c\-449b\-9121\-55cd37f6383e/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/Necro-Stealer
        $string5 = /d14be0c5477fc937b2cc00367931e1181d8897ce98a560cff48e0939840a096b/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/Necro-Stealer
        $string6 = /NecroStealer\.exe/ nocase ascii wide
        // Description: C++ stealer (passwords - cookies - forms - cards - wallets) 
        // Reference: https://github.com/SecUser1/Necro-Stealer
        $string7 = /SecUser1\/Necro\-Stealer/ nocase ascii wide

    condition:
        any of them
}
