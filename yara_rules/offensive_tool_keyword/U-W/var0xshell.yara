rule var0xshell
{
    meta:
        description = "Detection patterns for the tool 'var0xshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "var0xshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string1 = /\sObfuscated\-Code\.py/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string2 = /\#Author\sYehia\sElghaly/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string3 = /\#Bind\sShell\s\(Client\)\s\(XOR\sAlgorithm\)/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string4 = /\/Obfuscated\-Code\.py/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string5 = /\/var0xshell\.git/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string6 = /\\Obfuscated\-Code\.py/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string7 = /b80bb505227429df0b61a07d2ab57c02a48043fbd90d4680192b1698e9a2f37a/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string8 = /e376445d4c432d5f3c61e4584974941028c2975b97ee1461e4f00c65eb09a0ed/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string9 = /e379046040e17b60f1311e1d406a5bd9e34fd3f8b9e22cbceed612a6c3a689a9/ nocase ascii wide
        // Description: var0xshell - shell with xor encryption
        // Reference: https://github.com/yehia-mamdouh/var0xshell/tree/main
        $string10 = /yehia\-mamdouh\/var0xshell/ nocase ascii wide

    condition:
        any of them
}
