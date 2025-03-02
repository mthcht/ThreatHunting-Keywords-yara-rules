rule LummaC2_Stealer_sample
{
    meta:
        description = "Detection patterns for the tool 'LummaC2-Stealer-sample' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "LummaC2-Stealer-sample"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string1 = "%appdaedx765ta%/Binaedx765nce" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string2 = "%appdedx765ata%/Eledx765ectrum" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string3 = "%appdedx765ata%/Etheedx765reum" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string4 = "%localaedx765ppdata%" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string5 = "%loedx765calappedx765data" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string6 = "%userproedx765file%" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string7 = /\.edx765txt/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string8 = /\\\\Edge\\\\Usedx765er\sData/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string9 = /\\\\Locedx765al\sStaedx765te/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string10 = /apedx765p\-stoedx765re\.jsedx765on/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string11 = "Binedx765ance Chaedx765in Waledx765let" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string12 = /Brex765ave\-Broedx765wser\\\\Usedx765er\sData/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string13 = /Chredx765ome\\\\Usedx765er\sDatedx765a/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string14 = /Chroedx765mium\\\\Useedx765r\sData/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string15 = "Extedx765ensioedx765ns/" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string16 = "ExtractFileInfoViaNTDLL" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string17 = /ExtractFirefoxProfileData\(/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string18 = "Importedx765ant Fileedx765s/Proedx765file" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string19 = "keystedx765ore" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string20 = /Komedx765eta\\\\Usedx765er\sDaedx765ta/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string21 = "Locedx765al Extensedx765ion Settinedx765gs" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string22 = "Loedx765gin Daedx765ta" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string23 = "Logedx765in Daedx765ta Foedx765r Accedx765ount" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string24 = "Meedx765taMaedx765sk" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string25 = "Micedx765rosoft" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string26 = /Moedx765zilla\\\\Firedx765efox\\\\Profedx765iles/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string27 = "Moziedx765lla Firefedx765ox" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string28 = /Netwedx765ork\\\\Cookedx765ies/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string29 = /Opedx765era\sNeoedx765n\\\\Usedx765er\sDaedx765ta/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string30 = /Opedx765era\sSoftwedx765are\\\\Opedx765era\sGX\sStaedx765ble/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string31 = /Opeedx765ra\sSoftedx765ware\\\\Opedx765era\sStaedx765ble/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string32 = "resutlStrBrwsrOfshit" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string33 = "Ronedx765in Walledx765et" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string34 = "Troedx765nLiedx765nk" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string35 = /Viedx765valdi\\\\Usedx765er\sData/ nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string36 = "Walledx765ets/Binanedx765ce" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string37 = "Walledx765ets/Eleedx765ctrum" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string38 = "Walledx765ets/Ethedx765ereum" nocase ascii wide
        // Description: artifacts from a specific sample of lumma stealer - source code on github
        // Reference: https://github.com/x86byte/LummaC2-Stealer
        $string39 = "Wedx765eb Daedx765ta" nocase ascii wide

    condition:
        any of them
}
