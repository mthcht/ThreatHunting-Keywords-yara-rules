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
        $string1 = /.{0,1000}\/Jormungandr\.git.{0,1000}/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string2 = /.{0,1000}\\\\\?\?\\\\Jormungandr.{0,1000}/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string3 = /.{0,1000}COFFLdr\.cpp.{0,1000}/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string4 = /.{0,1000}COFFLdr\.exe.{0,1000}/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string5 = /.{0,1000}Idov31\/Jormungandr.{0,1000}/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string6 = /.{0,1000}Jormungandr\.cpp.{0,1000}/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string7 = /.{0,1000}Jormungandr\.exe.{0,1000}/ nocase ascii wide
        // Description: Jormungandr is a kernel implementation of a COFF loader allowing kernel developers to load and execute their COFFs in the kernel
        // Reference: https://github.com/Idov31/Jormungandr
        $string8 = /.{0,1000}Jormungandr\-master.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
