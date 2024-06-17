rule UACME
{
    meta:
        description = "Detection patterns for the tool 'UACME' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "UACME"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string1 = /\/UacInfo64\.exe/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string2 = /\/UACME\.git/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string3 = /\\UacInfo64\.exe/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string4 = /\\UACME\-.{0,1000}\.zip/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string5 = /051b9812bd48685cd19ba31247a3cb50a845bb902feae2433ff1fd8840a6e520/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string6 = /06a0846262867cf39dcbd90d3be0d19470692f828cd24b9ed7c4b13dae8e02c5/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string7 = /07EF7652\-1C2D\-478B\-BB4B\-F9560695A387/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string8 = /1565f9e89e6675525375dcb0e69cf08ef9a77a3d5bba36f89266a2c098dc6bda/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string9 = /210A3DB2\-11E3\-4BB4\-BE7D\-554935DCCA43/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string10 = /23A2E629\-DC9D\-46EA\-8B5A\-F1D60566EA09/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string11 = /304D5A8A\-EF98\-4E21\-8F4D\-91E66E0BECAC/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string12 = /32d18b1f5e53d194a9875e279d9a9ce2c8beb912f53f38877ec61bef2cb49bec/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string13 = /33905c6c09d7bfd90a6afa48e1ba9bf6349439cb1b397f7981970631c11a4dfb/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string14 = /3727f61b04be843ce0f423136f75180489433da44ad8dc9c948ca0008c7368eb/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string15 = /3855e59bb3240198350cfa740f6a568f4f7510e174ec37f08a385dddd31cb0c6/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string16 = /3BEF8A16\-981F\-4C65\-8AE7\-C612B46BE446/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string17 = /44dd7375f1bd3e113d15aac2634839f6a33b8706f27540f6b098e85866373ed4/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string18 = /5e1d5d651348c7b8066cab1d5341b7f38fb8271a7ff6add68876e7f83cbecf63/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string19 = /64f2cdd3e097e191e0395ae0ac0f0f443387ab3a881a2f6baddfc53cd7bfb93f/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string20 = /690b998d1f9a9f3b67f8a78771f9c88ad5455c2b0150c92b2960fa69f196f660/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string21 = /706cab3e36eec233139d8b353970343383d32d87fa1eb722c5cef1ca3511256a/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string22 = /82d3a3d0a5004b0079166839cdc9c570a6d861954f62f50d22053206a298c5f9/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string23 = /aa6e70c1f44cc2d9ff2fd6ad67ffc7ff63d33bd63cf1059e185a588f9e0cc0ff/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string24 = /b1505d27a4a0eda62dc0b193d635f01998e927e21b61dfcb7cb0e6c721a1cf65/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string25 = /c0e65b802e813fd274aaba62a4b321210d7e55f27c7ee65516d046f9867d734e/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string26 = /d9b1338f0cd7c0166a66b809e6c0519efbc37ad5b6a318454daa6f71693ba910/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string27 = /ddf0d053a9ee7c4f7d1b1965a976ddfb3792c7703ff81fafb9a3758a45c86f9c/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string28 = /e4221478f87a8403a8db34b908d0b1d42e4b76cec95835364d2310b77cc2615d/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string29 = /e43f95f83949e27b099ea863b18f8fdb42d5c50d58f846051fa15c0cd2e9d491/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string30 = /e9bddaa720ae081b0ef421bc7c8def328fecb3b4802e4d701297f421473b05bc/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string31 = /f37b4f47af2c937cd6ca8f380f2715c1b3fa9f97bd11d5abcac41e2e05a83c62/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string32 = /hfiref0x\.github\.io\/Beacon\/uac\/exec/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string33 = /hfiref0x\/UACME/ nocase ascii wide
        // Description: Defeating Windows User Account Control by abusing built-in Windows AutoElevate backdoor.
        // Reference: https://github.com/hfiref0x/UACME
        $string34 = /UACME\-master/ nocase ascii wide

    condition:
        any of them
}
