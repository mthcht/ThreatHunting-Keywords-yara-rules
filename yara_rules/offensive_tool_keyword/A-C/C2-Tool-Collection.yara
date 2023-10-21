rule C2_Tool_Collection
{
    meta:
        description = "Detection patterns for the tool 'C2-Tool-Collection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C2-Tool-Collection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string1 = /\/C2\-Tool\-Collection\// nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string2 = /\/SprayAD\.exe/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string3 = /\\SprayAD\.cna/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string4 = /\\SprayAD\.exe/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string5 = /Lapsdump\.cna/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string6 = /Lapsdump\.exe/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string7 = /PetitPotam\.cna/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string8 = /PetitPotam\.exe/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string9 = /PetitPotam\.ps1/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string10 = /PetitPotam\.sln/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string11 = /PetitPotam\.vcxproj/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string12 = /ReflectiveDll\./ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string13 = /ReflectiveDLLInjection\./ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string14 = /ReflectiveLoader\./ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string15 = /TicketToHashcat\.py/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string16 = /Lapsdump\s/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string17 = /SprayAD\s.*\s.*\s/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string18 = /SprayAD\.exe\s/ nocase ascii wide

    condition:
        any of them
}