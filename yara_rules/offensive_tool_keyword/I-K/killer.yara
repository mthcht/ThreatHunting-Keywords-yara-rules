rule killer
{
    meta:
        description = "Detection patterns for the tool 'killer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "killer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string1 = /\skiller\.cpp\s/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string2 = /\skiller\.exe/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string3 = /\sreverse\-shellcode\.cpp/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string4 = /\sshellcode\-xor\.py/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string5 = /\/killer\.exe/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string6 = /\/Killer\.git/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string7 = /\/reverse\-shellcode\.cpp/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string8 = /\/shellcode\-xor\.py/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string9 = /\\killer\.cpp/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string10 = /\\killer\.exe/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string11 = /\\nReversed\sshellcode\:\\n/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string12 = /\\reverse\-shellcode\.cpp/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string13 = /\\shellcode\-xor\.py/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string14 = "0xHossam/Killer" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string15 = "26695658d9cd9108527921dc351de3b717d37d849d0390ad7b9a6f0bb4d474a9" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string16 = "3d0ab78d9ceb76cae4a8a600ebfcf3e078ccc5b19038edf73fcf9653f26d7064" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string17 = "Author => Hossam Ehab / EDR/AV evasion tool" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string18 = /Author\:\sHossam\sEhab\s\-\sfacebook\.com\/0xHossam/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string19 = "b84798b914f570f9b52bf3fe754c2559795aa6c3daa4c4344f4bce69f5f759d9" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string20 = "c0e4815479886635396488093956d7926bcd803a4651c715398cf4446a05a55f" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string21 = "Hit enter to run shellcode/payload without creating a new thread" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string22 = "Killer tool for EDR/AV Evasion --> IAT Obfuscation" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string23 = /Sandbox\sdetected\s\-\sFilename\schanged\s\:\(\s/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string24 = "Shellcode & key Decrypted after stomping" nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string25 = /\'W\'\,\'i\'\,\'n\'\,\'d\'\,\'o\'\,\'w\'\,\'s\'\,\'\\\\\'\,\'S\'\,\'y\'\,\'s\'\,\'t\'\,\'e\'\,\'m\'\,\'3\'\,\'2\'\,/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string26 = "windows/x64/meterpreter/reverse_tcp" nocase ascii wide

    condition:
        any of them
}
