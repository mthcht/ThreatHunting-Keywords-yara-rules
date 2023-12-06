rule nimplant
{
    meta:
        description = "Detection patterns for the tool 'nimplant' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nimplant"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string1 = /\s\-d:sleepmask/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string2 = /\sexe\-selfdelete/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string3 = /\s\-\-nomain\s\-d:exportDll\s\-\-passL:/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string4 = /\.nimplant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string5 = /\.ShellcodeRDI/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string6 = /\/NimPlant\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string7 = /\/NimPlant\// nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string8 = /\/nimplants\// nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string9 = /\\NimPlant\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string10 = /_nimplant_/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string11 = /127\.0\.0\.1:31337/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string12 = /789CF3CBCC0DC849CC2B51703652084E2D2A4B2D02003B5C0650/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string13 = /BeaconGetSpawnTo/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string14 = /BeaconInjectProcess/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string15 = /C2\sClient/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string16 = /C2\sNimplant\sServer/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string17 = /Cannot\senumerate\santivirus/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string18 = /chvancooten\/nimbuild/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string19 = /chvancooten\/NimPlant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string20 = /Cmd\-Execute\-Assembly\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string21 = /Cmd\-Inline\-Execute\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string22 = /Cmd\-Shinject\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string23 = /Cmd\-Upload\./ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string24 = /compile_implant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string25 = /ConvertToShellcode/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string26 = /dbGetNimplant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string27 = /details\-c80a6994018b23dc\.js/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string28 = /execute\-assembly\s/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string29 = /executeAssembly\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string30 = /f4081a8e30f75d46\.js/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string31 = /fde1b109f9704ff7\.css/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string32 = /framework\-114634acb84f8baa\.js/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string33 = /getLocalAdm/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string34 = /getNimplantByGuid/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string35 = /getPositionImplant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string36 = /import\snp_server/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string37 = /inline\-execute\s.{0,1000}\.o/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string38 = /inlineExecute\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string39 = /killAllNimplants/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string40 = /localhost:31337/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string41 = /NimPlant\sv/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string42 = /nimplant\-/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string43 = /NimPlant.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string44 = /NimPlant.{0,1000}\.zip/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string45 = /nimplant\.db/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string46 = /NimPlant\.dll/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string47 = /NimPlant\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string48 = /NimPlant\.nimble/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string49 = /NimPlant\.py/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string50 = /nimplantPrint/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string51 = /nimplants\-.{0,1000}\.js/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string52 = /nimplants\.html/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string53 = /\-selfdelete\.exe\s\-d:selfdelete/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string54 = /server\-7566091c4e4a2a24\.js/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string55 = /shell\s\'cmd\.exe\s\/c/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string56 = /ShellcodeRDI\.py/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string57 = /shinject\s/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string58 = /shinject\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string59 = /util\.nimplant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string60 = /whoami\.nim/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string61 = /zippy\.nim/ nocase ascii wide
        // Description: user agent default field - A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string62 = /nimplant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string63 = /nimplant\s/ nocase ascii wide

    condition:
        any of them
}
