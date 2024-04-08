rule NetshHelperBeacon
{
    meta:
        description = "Detection patterns for the tool 'NetshHelperBeacon' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NetshHelperBeacon"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string1 = /\/NetshHelperBeacon\.git/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string2 = /\\NetshHelperBeacon\.cpp/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string3 = /\\NetshHelperBeacon\.dll/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string4 = /\\NetshHelperBeacon\.lib/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string5 = /\\NetshHelperBeacon\.log/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string6 = /\\NetshHelperBeacon\.pdb/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string7 = /\\NetshHelperBeacon\\/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string8 = /\\xfc\\x48\\x83\\xe4\\xf0\\xe8\\xc8\\x00\\x00\\x00\\x41\\x51\\x41\\x50\\x52\\x51\\x56\\x48\\x31\\xd2\\x65\\x48\\x8b\\x52\\x60\\x48\\x8b\\x52\\x18\\x48\\x8b\\x52\\x20\\x48\\x8b\\x72\\x50\\x48\\x0f\\xb7\\x4a\\x4a\\x4d\\x31\\xc9\\x48\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\x41\\xc1\\xc9\\x0d\\x41\\x01\\xc1\\xe2\\xed\\x52\\x41\\x51\\x48/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string9 = /\\xfc\\xe8\\x89\\x00\\x00\\x00\\x60\\x89\\xe5\\x31\\xd2\\x64\\x8b\\x52\\x30\\x8b\\x52\\x0c\\x8b\\x52\\x14\\x8b\\x72\\x28\\x0f\\xb7\\x4a\\x26\\x31\\xff\\x31\\xc0\\xac\\x3c\\x61\\x7c\\x02\\x2c\\x20\\xc1\\xcf\\x0d\\x01\\xc7\\xe2\\xf0\\x52\\x57\\x8b\\x52\\x10\\x8b\\x42\\x3c\\x01\\xd0\\x8b\\x40\\x78\\x85\\xc0\\x74\\x4a\\x01\\xd0\\x50\\x8b\\x48\\/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string10 = /3BB0CD58\-487C\-4FEC\-8001\-607599477158/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string11 = /93b20a7961c9986baf181d1a1635b33b87735f75d046c6dcdd5d412a55832d6f/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string12 = /9ecca3b6c787675d74bbfaa0e3ded77d448a0de4fe51c3c29c07cf3b04b8b71d/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string13 = /a84e1abea8327bcede6dfb79b50b36780f2e1cdb8166002d75c070574a83738f/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string14 = /NetshHelperBeacon\.exe/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string15 = /outflanknl\/NetshHelperBeacon/ nocase ascii wide
        // Description: DLL to load from Windows NetShell. Will pop calc and execute shellcode.
        // Reference: https://github.com/outflanknl/NetshHelperBeacon
        $string16 = /Simple\scode\sfor\screating\sa\sDLL\sfor\snetsh\shelper\sDLLs/ nocase ascii wide

    condition:
        any of them
}
