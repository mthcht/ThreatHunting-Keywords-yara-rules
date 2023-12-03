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
        $string1 = /.{0,1000}\/PetitPotam\.git.{0,1000}/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string2 = /.{0,1000}PetitPotam\.cpp.{0,1000}/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string3 = /.{0,1000}PetitPotam\.exe.{0,1000}/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string4 = /.{0,1000}PetitPotam\.py.{0,1000}/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string5 = /.{0,1000}PetitPotam\.sln.{0,1000}/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string6 = /.{0,1000}topotam\.exe.{0,1000}/ nocase ascii wide
        // Description: PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.
        // Reference: https://github.com/topotam/PetitPotam
        $string7 = /.{0,1000}topotam\/PetitPotam.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
