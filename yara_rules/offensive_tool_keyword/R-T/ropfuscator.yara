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
        $string1 = /\sropfuscator/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string2 = /\/ropfuscator/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string3 = /ROPEngine\.cpp/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string4 = /ropfuscator\s/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string5 = /ROPfuscator/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string6 = /ropfuscator\-/ nocase ascii wide
        // Description: ROPfuscator is a fine-grained code obfuscation framework for C/C++ programs using ROP (return-oriented programming).
        // Reference: https://github.com/ropfuscator/ropfuscator
        $string7 = /ropfuscator\./ nocase ascii wide

    condition:
        any of them
}
