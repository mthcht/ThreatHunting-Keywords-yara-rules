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
        $string1 = /\/ntdlll\-unhooking\-collection/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string2 = /\\ntdlll\-unhooking\-collection/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string3 = /0472A393\-9503\-491D\-B6DA\-FA47CD567EDE/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string4 = /1C5EDA8C\-D27F\-44A4\-A156\-6F863477194D/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string5 = /4DE43724\-3851\-4376\-BB6C\-EA15CF500C44/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string6 = /DA230B64\-14EA\-4D49\-96E1\-FA5EFED9010B/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string7 = /Ntdll_SusProcess\./ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string8 = /RemoteNTDLL\.cpp/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string9 = /RemoteNTDLL\.exe/ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string10 = /UnhookingKnownDlls\./ nocase ascii wide
        // Description: unhooking ntdll from disk - from KnownDlls - from suspended process - from remote server (fileless)
        // Reference: https://github.com/TheD1rkMtr/ntdlll-unhooking-collection
        $string11 = /UnhookingNtdll_disk\./ nocase ascii wide

    condition:
        any of them
}
