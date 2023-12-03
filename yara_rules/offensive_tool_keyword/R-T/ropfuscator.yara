rule ropfuscator
{
    meta:
        description = "Detection patterns for the tool 'ropfuscator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ropfuscator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string1 = /.{0,1000}\sropfuscator.{0,1000}/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string2 = /.{0,1000}\/ropfuscator.{0,1000}/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string3 = /.{0,1000}ROPEngine\.cpp.{0,1000}/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string4 = /.{0,1000}ropfuscator\s.{0,1000}/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string5 = /.{0,1000}ROPfuscator.{0,1000}/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string6 = /.{0,1000}ropfuscator\-.{0,1000}/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string7 = /.{0,1000}ropfuscator\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
