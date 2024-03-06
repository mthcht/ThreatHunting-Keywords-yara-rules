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
        $string1 = /\/mimikatz\.enc/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string2 = /\/mortar\.git/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string3 = /\/mortar\/releases\/download\/v2\/encryptor/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string4 = /\\mortar\\Lib\\shell_loader\.pas/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string5 = /\\pipe\\moj_ML_ntsvcs\s/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string6 = /0xsp\-SRD\/mortar/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string7 = /cmd\.exe\s\/c\srundll32\.exe\sagressor\.dll.{0,1000}stealth/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string8 = /deliver\.exe\s\-d\s\-c\s.{0,1000}\s\-f.{0,1000}\.enc/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string9 = /deliver\.exe\s\-d\s\-f\s.{0,1000}\.enc/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string10 = /encryptor\s\-f\s.{0,1000}\.exe\s\-o\s.{0,1000}\.enc/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string11 = /mortar\-loader\.html/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string12 = /mortar\-main\.zip/ nocase ascii wide
        // Description: red teaming evasion technique to defeat and divert detection and prevention of security products.Mortar Loader performs encryption and decryption of selected binary inside the memory streams and execute it directly with out writing any malicious indicator into the hard-drive. Mortar is able to bypass modern anti-virus products and advanced XDR solutions
        // Reference: https://github.com/0xsp-SRD/mortar
        $string13 = /rundll32\.exe\sagressor\.dll.{0,1000}dec/ nocase ascii wide

    condition:
        any of them
}
