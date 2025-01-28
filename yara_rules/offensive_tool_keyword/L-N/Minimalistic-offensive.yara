rule Minimalistic_offensive
{
    meta:
        description = "Detection patterns for the tool 'Minimalistic-offensive' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Minimalistic-offensive"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string1 = "# Minimalistic AD login bruteforcer " nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string2 = "# Minimalistic SMB login bruteforcer " nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string3 = "# Minimalistic TCP and UDP port scanners" nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string4 = /\/adlogin\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string5 = /\/localbrute\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string6 = /\/localbrute\-extra\-mini\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string7 = /\/Minimalistic\-offensive\-security\-tools\.git/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string8 = /\/port\-scan\-tcp\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string9 = /\/port\-scan\-udp\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string10 = /\/smblogin\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string11 = /\\adlogin\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string12 = /\\localbrute\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string13 = /\\localbrute\-extra\-mini\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string14 = /\\port\-scan\-tcp\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string15 = /\\port\-scan\-udp\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string16 = /\\smblogin\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string17 = /\\smblogin\.results\.txt/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string18 = /\\smblogin\-extra\-mini\.ps1/ nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string19 = "288b02056109591e230be8268e3e41c61f791d0025008050fc1a558118234259" nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string20 = "374356feb445591acf371af512a66c6197f8a18613f41988cc7357b27c738a94" nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string21 = "43c40eb82cecff19379a8de93b36686149eded614d1dfbdabd31e3fb9e6f3fc6" nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string22 = "64005eea1af219477177e1f5a2479f4214705ef814f2ca2e70d921bf696b0808" nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string23 = "6fb86b256e278c854acf21be16797fb8d774759982cd3251ffda758260dffd44" nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string24 = "87f28c29263f95595eaa3c35a9091eaa5ccadce9f84738309f8781328465ede2" nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string25 = "96c4151c60a745d0ad96649cd6589dd28fb8e4761de75a425965315a3aab2d62" nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string26 = "b4a463948663e6a142ddbbc35f9ef543da818497acfdf21c21ec2bd96bc53fa6" nocase ascii wide
        // Description: A repository of tools for pentesting of restricted and isolated environments.
        // Reference: https://github.com/InfosecMatter/Minimalistic-offensive-security-tools
        $string27 = "InfosecMatter/Minimalistic-offensive-security-tools" nocase ascii wide

    condition:
        any of them
}
