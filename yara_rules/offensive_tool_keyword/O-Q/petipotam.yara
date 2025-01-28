rule petipotam
{
    meta:
        description = "Detection patterns for the tool 'petipotam' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "petipotam"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string1 = /\/PetitPotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string2 = /\/PetitPotam\.git/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string3 = /\[\-\]\sGot\sRPC_ACCESS_DENIED\!\!\sEfsRpcOpenFileRaw\sis\sprobably\sPATCHED\!/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string4 = /\\PetitPotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string5 = "3989cbea4af22774f0fa20d10b88c7247e675be8b9ec9dae716a44cb36d50189" nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string6 = "D78924E1-7F2B-4315-A2D2-24124C7828F8" nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string7 = /GILLES\sLionel\saka\stopotam\s\(\@topotam77\)/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string8 = /PetitPotam\.cpp/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string9 = /PetitPotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string10 = /PetitPotam\.py/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string11 = /PetitPotam\.sln/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string12 = "PetitPotam:main" nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string13 = /topotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string14 = "topotam/PetitPotam" nocase ascii wide

    condition:
        any of them
}
