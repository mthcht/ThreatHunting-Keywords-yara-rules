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
        $string1 = /.{0,1000}\/hyperion\.exe.{0,1000}/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string2 = /.{0,1000}\/windows\-resources\/hyperion.{0,1000}/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string3 = /.{0,1000}\\hyperion\.exe.{0,1000}/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string4 = /.{0,1000}apt\sinstall\shyperion.{0,1000}/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string5 = /.{0,1000}Hyperion\sPE\-Crypter.{0,1000}/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string6 = /.{0,1000}hyperion\.exe\s.{0,1000}/ nocase ascii wide
        // Description: A runtime PE-Crypter - The crypter is started via the command line and encrypts an input executable with AES-128. The encrypted file decrypts itself on startup (bruteforcing the AES key which may take a few seconds)
        // Reference: https://www.kali.org/tools/hyperion/
        $string7 = /.{0,1000}hyperion_2\.0\.orig\.tar\.gz.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
