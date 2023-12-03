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
        $string1 = /.{0,1000}\/C2\-Tool\-Collection\/.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string2 = /.{0,1000}\/SprayAD\.exe.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string3 = /.{0,1000}\\SprayAD\.cna.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string4 = /.{0,1000}\\SprayAD\.exe.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string5 = /.{0,1000}Lapsdump\.cna.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string6 = /.{0,1000}Lapsdump\.exe.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string7 = /.{0,1000}PetitPotam\.cna.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string8 = /.{0,1000}PetitPotam\.exe.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string9 = /.{0,1000}PetitPotam\.ps1.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string10 = /.{0,1000}PetitPotam\.sln.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string11 = /.{0,1000}PetitPotam\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string12 = /.{0,1000}ReflectiveDll\..{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string13 = /.{0,1000}ReflectiveDLLInjection\..{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string14 = /.{0,1000}ReflectiveLoader\..{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string15 = /.{0,1000}SprayAD\.exe\s.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string16 = /.{0,1000}TicketToHashcat\.py.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string17 = /Lapsdump\s.{0,1000}/ nocase ascii wide
        // Description: A collection of tools which integrate with Cobalt Strike (and possibly other C2 frameworks) through BOF and reflective DLL loading techniques
        // Reference: https://github.com/outflanknl/C2-Tool-Collection
        $string18 = /SprayAD\s.{0,1000}\s.{0,1000}\s/ nocase ascii wide

    condition:
        any of them
}
