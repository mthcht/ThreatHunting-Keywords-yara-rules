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
        $string14 = /\\xfc\\xe8\\x82\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xc0\\x64\\x8b\\x50\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28\\x0f\\xb7\\x4a\\x26\\x31\\xff\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\xe2\\xf2\\x52\\x57\\x8b\\x52\\x10\\x8b\\x4a\\x3c\\x8b\\x4c\\x11\\x78\\xe3\\x48\\x01\\xd1\\x51\\x8b\\x59\\x20\\x01\\xd3\\x8b\\x49\\x18\\xe3\\x3a\\x49\\x8b\\x34\\x8b\\x01\\xd6\\x31\\xff\\xac\\xc1\\xcf\\x0d\\x01\\xc7\\x38\\xe0\\x75\\xf6\\x03\\x7d\\xf8\\x3b\\x7d\\x24\\x75\\xe4\\x58\\x8b\\x58\\x24\\x01\\xd3\\x66\\x8b\\x0c\\x4b\\x8b\\x58\\x1c\\x01\\xd3\\x8b\\x04\\x8b\\x01\\xd0\\x89\\x44\\x24\\x24\\x5b\\x5b\\x61\\x59\\x5a\\x51\\xff\\xe0\\x5f\\x5f\\x5a\\x8b\\x12\\xeb\\x8d\\x5d\\x6a\\x01\\x8d\\x85\\xb2\\x00\\x00\\x00\\x50\\x68\\x31\\x8b\\x6f\\x87\\xff\\xd5\\xbb\\xf0\\xb5\\xa2\\x56\\x68\\xa6\\x95\\xbd\\x9d\\xff\\xd5\\x3c\\x06\\x7c\\x0a\\x80\\xfb\\xe0\\x75\\x05\\xbb\\x47\\x13\\x72\\x6f\\x6a\\x00\\x53\\xff\\xd5\\x63\\x61\\x6c\\x63\\x2e\\x65\\x78\\x65\\x00/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string15 = /0xb4\,\s0x27\,\s0xb4\,\s0x97\,\s0xb1\,\s0xa5\,\s0xf3\,\s0x45\,\s0x68\,\s0x30\,\s0x3\,\s0x10\,\s0x74\,\s0x3c\,\s0x2\,\s0x0\,\s0x21\,\s0x7a\,\s0x4b\,\s0x8a\,\s0x12\,\s0x7b\,\s0xc5\,\s0x1a\,\s0xf\,\s0x7f\,\s0xf8\,\s0x13\,\s0x55\,\s0x7b\,\s0xce\,\s0x3a\,\s0x10\,\s0xa\,\s0xca\,\s0x47\,\s0x3c\,\s0x18\,\s0x5e\,\s0xc0\,\s0x78\,\s0x30\,\s0x15\,\s0x46\,\s0xfa\,\s0x6\,\s0x79\,\s0xaf\,\s0x9b\,\s0x4f\,\s0x20\,\s0x31\,\s0x31\,\s0x69\,\s0x48\,\s0x71\,\s0x83\,\s0x88\,\s0x38\,\s0x2d\,\s0x51\,\s0x90\,\s0x95\,\s0xdf\,\s0x28\,\s0x19\,\s0x26\,\s0x7b\,\s0xc5\,\s0x1a\,\s0x4f\,\s0xbc\,\s0x31\,\s0x7d\,\s0x5\,\s0x32\,\s0x95\,\s0xe3\,\s0xb0\,\s0xca\,\s0x41\,\s0x35\,\s0x6c\,\s0x18\,\s0xd4\,\s0xb7\,\s0x46\,\s0x1d\,\s0x10\,\s0x76\,\s0xe3\,\s0x1e\,\s0xc3\,\s0x27\,\s0x2f\,\s0x37\,\s0xca\,\s0xd\,\s0x13\,\s0xc\,\s0x69\,\s0xe0\,\s0xa1\,\s0x17\,\s0x7d\,\s0x93\,\s0x99\,\s0x10\,\s0xfc\,\s0x6\,\s0xf2\,\s0x10\,\s0x76\,\s0xe5\,\s0x3\,\s0x79\,\s0xa6\,\s0x7f\,\s0x42\,\s0x81\,\s0xe1\,\s0x72\,\s0x84\,\s0xa1\,\s0x3d\,\s0x3\,\s0x40\,\s0xf4\,\s0x54\,\s0xb0\,\s0x24\,\s0x86\,\s0x7e\,\s0x79/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string16 = /0xHossam\/Killer/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string17 = /26695658d9cd9108527921dc351de3b717d37d849d0390ad7b9a6f0bb4d474a9/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string18 = /3d0ab78d9ceb76cae4a8a600ebfcf3e078ccc5b19038edf73fcf9653f26d7064/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string19 = /Author\s\=\>\sHossam\sEhab\s\/\sEDR\/AV\sevasion\stool/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string20 = /Author\:\sHossam\sEhab\s\-\sfacebook\.com\/0xHossam/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string21 = /b84798b914f570f9b52bf3fe754c2559795aa6c3daa4c4344f4bce69f5f759d9/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string22 = /c0e4815479886635396488093956d7926bcd803a4651c715398cf4446a05a55f/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string23 = /Hit\senter\sto\srun\sshellcode\/payload\swithout\screating\sa\snew\sthread/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string24 = /Killer\stool\sfor\sEDR\/AV\sEvasion\s\-\-\>\sIAT\sObfuscation/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string25 = /Sandbox\sdetected\s\-\sFilename\schanged\s\:\(\s/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string26 = /Shellcode\s\&\skey\sDecrypted\safter\sstomping/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string27 = /\'W\'\,\'i\'\,\'n\'\,\'d\'\,\'o\'\,\'w\'\,\'s\'\,\'\\\\\'\,\'S\'\,\'y\'\,\'s\'\,\'t\'\,\'e\'\,\'m\'\,\'3\'\,\'2\'\,/ nocase ascii wide
        // Description: evade AVs and EDRs or security tools
        // Reference: https://github.com/0xHossam/Killer
        $string28 = /windows\/x64\/meterpreter\/reverse_tcp/ nocase ascii wide

    condition:
        any of them
}
