rule ntdlll_unhooking_collection
{
    meta:
        description = "Detection patterns for the tool 'ntdlll-unhooking-collection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ntdlll-unhooking-collection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string1 = /.{0,1000}\/ntdlll\-unhooking\-collection.{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string2 = /.{0,1000}\\ntdlll\-unhooking\-collection.{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string3 = /.{0,1000}0472A393\-9503\-491D\-B6DA\-FA47CD567EDE.{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string4 = /.{0,1000}1C5EDA8C\-D27F\-44A4\-A156\-6F863477194D.{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string5 = /.{0,1000}4DE43724\-3851\-4376\-BB6C\-EA15CF500C44.{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string6 = /.{0,1000}DA230B64\-14EA\-4D49\-96E1\-FA5EFED9010B.{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string7 = /.{0,1000}Ntdll_SusProcess\..{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string8 = /.{0,1000}RemoteNTDLL\.cpp.{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string9 = /.{0,1000}RemoteNTDLL\.exe.{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string10 = /.{0,1000}UnhookingKnownDlls\..{0,1000}/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string11 = /.{0,1000}UnhookingNtdll_disk\..{0,1000}/ nocase ascii wide

    condition:
        any of them
}
