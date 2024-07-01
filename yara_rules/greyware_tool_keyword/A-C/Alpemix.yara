rule Alpemix
{
    meta:
        description = "Detection patterns for the tool 'Alpemix' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Alpemix"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string1 = /\/Alpemix\.zip/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string2 = /\/Apemix\.exe/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string3 = /\\Alpemix\.ini/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string4 = /\\Alpemix\.zip/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string5 = /\\Apemix\.exe/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string6 = /\\CurrentControlSet\\Services\\AlpemixSrvcx/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string7 = /\<Alpemix\>/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string8 = /\<AlpemixWEB\>/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string9 = /\<Teknopars\sBilisim\>/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string10 = /3660fe9f10b94d38fecaea009e6625850a46b1d47bb7788fc47f286c1008e2ec/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string11 = /6badff5495258b349559b9d2154ffcc7a435828dd57c4caf1c79f5d0ff9eb675/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string12 = /c5e68c5635bed872ce6ac0c2be5395cc15c2dbaa5f0052b86575cdd0b762902e/ nocase ascii wide
        // Description: connect to your unattended PC from anywhere
        // Reference: https://www.alpemix.com/
        $string13 = /serverinfo\.alpemix\.com/ nocase ascii wide

    condition:
        any of them
}
