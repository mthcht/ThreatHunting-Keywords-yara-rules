rule hyperion
{
    meta:
        description = "Detection patterns for the tool 'hyperion' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "hyperion"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string1 = /\/hyperion\.exe/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string2 = /\/windows\-resources\/hyperion/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string3 = /\\hyperion\.exe/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string4 = /apt\sinstall\shyperion/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string5 = /Hyperion\sPE\-Crypter/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string6 = /hyperion\.exe\s/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string7 = /hyperion_2\.0\.orig\.tar\.gz/ nocase ascii wide

    condition:
        any of them
}
