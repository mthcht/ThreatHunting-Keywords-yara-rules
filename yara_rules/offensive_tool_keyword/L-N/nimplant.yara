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
        $string1 = /.{0,1000}\s\-d:sleepmask.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string2 = /.{0,1000}\sexe\-selfdelete.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string3 = /.{0,1000}\s\-\-nomain\s\-d:exportDll\s\-\-passL:.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string4 = /.{0,1000}\.nimplant.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string5 = /.{0,1000}\.ShellcodeRDI.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string6 = /.{0,1000}\/NimPlant\..{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string7 = /.{0,1000}\/NimPlant\/.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string8 = /.{0,1000}\/nimplants\/.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string9 = /.{0,1000}\\NimPlant\..{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string10 = /.{0,1000}_nimplant_.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string11 = /.{0,1000}127\.0\.0\.1:31337.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string12 = /.{0,1000}789CF3CBCC0DC849CC2B51703652084E2D2A4B2D02003B5C0650.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string13 = /.{0,1000}BeaconGetSpawnTo.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string14 = /.{0,1000}BeaconInjectProcess.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string15 = /.{0,1000}C2\sClient.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string16 = /.{0,1000}C2\sNimplant\sServer.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string17 = /.{0,1000}Cannot\senumerate\santivirus.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string18 = /.{0,1000}chvancooten\/nimbuild.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string19 = /.{0,1000}chvancooten\/NimPlant.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string20 = /.{0,1000}Cmd\-Execute\-Assembly\..{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string21 = /.{0,1000}Cmd\-Inline\-Execute\..{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string22 = /.{0,1000}Cmd\-Shinject\..{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string23 = /.{0,1000}Cmd\-Upload\..{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string24 = /.{0,1000}compile_implant.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string25 = /.{0,1000}ConvertToShellcode.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string26 = /.{0,1000}dbGetNimplant.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string27 = /.{0,1000}details\-c80a6994018b23dc\.js.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string28 = /.{0,1000}execute\-assembly\s.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string29 = /.{0,1000}executeAssembly\.nim.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string30 = /.{0,1000}f4081a8e30f75d46\.js.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string31 = /.{0,1000}fde1b109f9704ff7\.css.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string32 = /.{0,1000}framework\-114634acb84f8baa\.js.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string33 = /.{0,1000}getLocalAdm.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string34 = /.{0,1000}getNimplantByGuid.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string35 = /.{0,1000}getPositionImplant.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string36 = /.{0,1000}import\snp_server.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string37 = /.{0,1000}inline\-execute\s.{0,1000}\.o.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string38 = /.{0,1000}inlineExecute\.nim.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string39 = /.{0,1000}killAllNimplants.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string40 = /.{0,1000}localhost:31337.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string41 = /.{0,1000}NimPlant\sv.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string42 = /.{0,1000}nimplant\-.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string43 = /.{0,1000}NimPlant.{0,1000}\.tar\.gz.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string44 = /.{0,1000}NimPlant.{0,1000}\.zip.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string45 = /.{0,1000}nimplant\.db.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string46 = /.{0,1000}NimPlant\.dll.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string47 = /.{0,1000}NimPlant\.nim.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string48 = /.{0,1000}NimPlant\.nimble.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string49 = /.{0,1000}NimPlant\.py.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string50 = /.{0,1000}nimplantPrint.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string51 = /.{0,1000}nimplants\-.{0,1000}\.js.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string52 = /.{0,1000}nimplants\.html.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string53 = /.{0,1000}\-selfdelete\.exe\s\-d:selfdelete.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string54 = /.{0,1000}server\-7566091c4e4a2a24\.js.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string55 = /.{0,1000}shell\s\'cmd\.exe\s\/c.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string56 = /.{0,1000}ShellcodeRDI\.py.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string57 = /.{0,1000}shinject\s.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string58 = /.{0,1000}shinject\.nim.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string59 = /.{0,1000}util\.nimplant.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string60 = /.{0,1000}whoami\.nim.{0,1000}/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string61 = /.{0,1000}zippy\.nim.{0,1000}/ nocase ascii wide
        // Description: user agent default field - A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string62 = /nimplant/ nocase ascii wide
        // Description: A light-weight first-stage C2 implant written in Nim
        // Reference: https://github.com/chvancooten/NimPlant
        $string63 = /nimplant\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
