rule mortar
{
    meta:
        description = "Detection patterns for the tool 'mortar' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mortar"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string1 = /.{0,1000}\.\/encryptor\s\-f\s.{0,1000}\.exe\s\-o\s.{0,1000}\.enc.{0,1000}/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string2 = /.{0,1000}\/mimikatz\.enc.{0,1000}/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string3 = /.{0,1000}0xsp\-SRD\/mortar.{0,1000}/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string4 = /.{0,1000}cmd\.exe\s\/c\srundll32\.exe\sagressor\.dll.{0,1000}stealth.{0,1000}/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string5 = /.{0,1000}deliver\.exe\s\-d\s\-c\s.{0,1000}\s\-f.{0,1000}\.enc.{0,1000}/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string6 = /.{0,1000}deliver\.exe\s\-d\s\-f\s.{0,1000}\.enc.{0,1000}/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string7 = /.{0,1000}mortar\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string8 = /.{0,1000}rundll32\.exe\sagressor\.dll.{0,1000}dec.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
