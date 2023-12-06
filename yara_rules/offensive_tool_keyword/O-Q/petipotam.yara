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
        $string1 = /\/PetitPotam\.git/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string2 = /PetitPotam\.cpp/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string3 = /PetitPotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string4 = /PetitPotam\.py/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string5 = /PetitPotam\.sln/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string6 = /topotam\.exe/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string7 = /topotam\/PetitPotam/ nocase ascii wide

    condition:
        any of them
}
