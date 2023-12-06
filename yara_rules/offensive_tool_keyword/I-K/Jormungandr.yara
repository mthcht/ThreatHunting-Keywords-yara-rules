rule Jormungandr
{
    meta:
        description = "Detection patterns for the tool 'Jormungandr' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jormungandr"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string1 = /\/Jormungandr\.git/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string2 = /\\\\\?\?\\\\Jormungandr/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string3 = /COFFLdr\.cpp/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string4 = /COFFLdr\.exe/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string5 = /Idov31\/Jormungandr/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string6 = /Jormungandr\.cpp/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string7 = /Jormungandr\.exe/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string8 = /Jormungandr\-master/ nocase ascii wide

    condition:
        any of them
}
