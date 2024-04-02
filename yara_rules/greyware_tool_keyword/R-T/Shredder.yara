rule Shredder
{
    meta:
        description = "Detection patterns for the tool 'Shredder' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shredder"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: File Shredder is FREE and powerfull aplication to shred and permanently remove unwanted files from your computer beyond recovery
        // Reference: https://www.fileshredder.org/
        $string1 = /\\file_shredder_setup\.tmp/ nocase ascii wide
        // Description: File Shredder is FREE and powerfull aplication to shred and permanently remove unwanted files from your computer beyond recovery
        // Reference: https://www.fileshredder.org/
        $string2 = /\\Shredder\.exe/ nocase ascii wide
        // Description: File Shredder is FREE and powerfull aplication to shred and permanently remove unwanted files from your computer beyond recovery
        // Reference: https://www.fileshredder.org/
        $string3 = /\>File\sShredder\sby\sPowTools\</ nocase ascii wide
        // Description: File Shredder is FREE and powerfull aplication to shred and permanently remove unwanted files from your computer beyond recovery
        // Reference: https://www.fileshredder.org/
        $string4 = /File\sShredder\ssetup\.exe/ nocase ascii wide
        // Description: File Shredder is FREE and powerfull aplication to shred and permanently remove unwanted files from your computer beyond recovery
        // Reference: https://www.fileshredder.org/
        $string5 = /File\sShredder\.exe/ nocase ascii wide
        // Description: File Shredder is FREE and powerfull aplication to shred and permanently remove unwanted files from your computer beyond recovery
        // Reference: https://www.fileshredder.org/
        $string6 = /file_shredder_setup\.exe/ nocase ascii wide
        // Description: File Shredder is FREE and powerfull aplication to shred and permanently remove unwanted files from your computer beyond recovery
        // Reference: https://www.fileshredder.org/
        $string7 = /Program\sFiles\\File\sShredder\\/ nocase ascii wide

    condition:
        any of them
}
