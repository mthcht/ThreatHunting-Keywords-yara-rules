rule ransomware_notes
{
    meta:
        description = "Detection patterns for the tool 'ransomware_notes' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ransomware_notes"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string1 = /\/atomsilo\.hta/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string2 = /\/crytox\.hta/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string3 = /\@evilmail\.to/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string4 = /\\\!\!\!file\swas\sstolen\!\!\!\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string5 = /\\\!\!\!READ_ME_MEDUSA\!\!\!\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string6 = /\\\!\!\!start\sleak\sfile\!\!\!\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string7 = /\\\!_\^_README_NOTES_RAGNAR_\^_\!\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string8 = /\\\!_karakurt_READ_ME_\!\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string9 = /\\\!_WHATS_HAPPENED_\!\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string10 = /\\\!_WHY_FILES_ARE_ENCRYPTED_\!\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string11 = /\\\#BlackHunt_ReadMe\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string12 = /\\\.README_TO_RESTORE/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string13 = /\\_Locky_recover_instructions\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string14 = /\\_READ_THIS_FILE_HBE8_\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string15 = /\\\+README\-WARNING\+\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string16 = /\\523XaDi1i\.README\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string17 = /\\8base_note\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string18 = /\\AAA_READ_AAA\.TXT/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string19 = /\\akira_readme\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string20 = /\\alphv1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string21 = /\\alphv2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string22 = /\\alphv3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string23 = /\\atomsilo\.hta/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string24 = /\\avaddon\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string25 = /\\avoslocker\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string26 = /\\AWAYOKON\-readme\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string27 = /\\BB_Readme\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string28 = /\\BB_Readme2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string29 = /\\bidon_readme\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string30 = /\\biglock\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string31 = /\\bitpaymer_v1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string32 = /\\bitpaymer_v2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string33 = /\\bitransomware\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string34 = /\\blackbasta1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string35 = /\\blackbasta2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string36 = /\\blackbasta3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string37 = /\\blackbasta4\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string38 = /\\blackbyte_v2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string39 = /\\cAcTuS\.readme\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string40 = /\\cAcTuS\.readme_2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string41 = /\\cAcTuS\.readme_3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string42 = /\\cAcTuS\.readme_4\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string43 = /\\cAcTuS\.readme_5\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string44 = /\\clop1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string45 = /\\clop2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string46 = /\\conti1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string47 = /\\conti2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string48 = /\\conti3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string49 = /\\conti4\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string50 = /\\CriticalBreachDetected\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string51 = /\\cryptomix\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string52 = /\\crytox\.hta/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string53 = /\\ctblocker\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string54 = /\\d0nut\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string55 = /\\dagonlocker\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string56 = /\\darkangels\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string57 = /\\Data\sbreach\swarning\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string58 = /\\DECRYPT\-FILES\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string59 = /\\diavol1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string60 = /\\diavol2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string61 = /\\doppelpaymer1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string62 = /\\doppelpaymer2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string63 = /\\doppelpaymer3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string64 = /\\doppelpaymer4\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string65 = /\\DtMXQFOCos\-RECOVER\-README\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string66 = /\\FILE\sRECOVERY\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string67 = /\\gandcrab\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string68 = /\\gwisinlocker\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string69 = /\\h0lygh0st\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string70 = /\\HELP_SECURITY_EVENT\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string71 = /\\HOW\sTO\sRECOVER\sYOUR\sFILES\.TXT/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string72 = /\\HOW\sTO\sRECOVERY\sFILES\.TXT/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string73 = /\\How\sto\sRestore\sYour\sFiles\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string74 = /\\How\sTo\sRestore\sYour\sFiles\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string75 = /\\HOW_RETURN_YOUR_DATA\.TXT/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string76 = /\\how_to_decrypt\.hta/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string77 = /\\HOW_TO_DECRYPT\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string78 = /\\HOW_TO_RECOVER_DATA\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string79 = /\\HOW_TO_RECOVER_FILES\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string80 = /\\HOW_TO_RECOVER_FILES_no_personal_id\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string81 = /\\HOW_TO_RECOVER_FILES_no_personal_id2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string82 = /\\HOW_TO_RECOVERY_FILES\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string83 = /\\How_To_Restore_Your_Files\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string84 = /\\iFire\-readme\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string85 = /\\INC\-README\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string86 = /\\INC\-README\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string87 = /\\INC\-README2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string88 = /\\INC\-README3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string89 = /\\INC\-README4\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string90 = /\\JX34qQm7\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string91 = /\\KARMA\-ENCRYPTED\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string92 = /\\lilith\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string93 = /\\lockbit2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string94 = /\\lockbit3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string95 = /\\Look\sat\sthis\sinstruction\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string96 = /\\nemty_v1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string97 = /\\nemty_v16\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string98 = /\\nemty_v25\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string99 = /\\netwalker\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string100 = /\\prometheus\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string101 = /\\quantumlocker\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string102 = /\\R3ADM3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string103 = /\\ragnarlocker1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string104 = /\\ragnarok\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string105 = /\\ransomexx1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string106 = /\\ransomexx2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string107 = /\\RansomNote\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string108 = /\\README\.BlackSuit\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string109 = /\\README_FOR_DECRYPT\.txtt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string110 = /\\readme_for_unlock\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string111 = /\\readme_for_unlock_2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string112 = /\\readme_for_unlock_3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string113 = /\\README_TO_DECRYPT\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string114 = /\\RECOVER\-FILES\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string115 = /\\RECOVERY_DARKBIT\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string116 = /\\RECOVERY_INSTRUCTIONS\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string117 = /\\Restore\sYour\sFiles\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string118 = /\\RESTORE_FILES\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string119 = /\\RESTORE\-FILES\-Q7ILknn7k\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string120 = /\\revil1\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string121 = /\\revil2\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string122 = /\\revil3\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string123 = /\\RFNCW\-DECRYPT\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string124 = /\\Risen_Guide\.hta/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string125 = /\\Risen_Guide2\.hta/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string126 = /\\Risen_Note\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string127 = /\\suncrypt\.html/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string128 = /\\teslacrypt\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string129 = /\\UNLOCK_FILES\..{0,1000}\.HTML/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string130 = /\\UNLOCK_MY_FILES\.txt/ nocase ascii wide
        // Description: ransomware note from knight ransomware
        // Reference: https://tria.ge/230901-c2fbqacb36
        $string131 = /\\Users\\How\sTo\sRestore\sYour\sFiles\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string132 = /\\vicesociety\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string133 = /\\wastedlocker\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string134 = /\\White_Rabbit\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string135 = /\\yanluowang\.txt/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string136 = "<h1>All your files was encrypted!" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string137 = /15010050\@tutamail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string138 = /1cd05248c2diffczd\.zgpnnj5ikwfugnfvmxzn3qaafstcrdwue4eevw2lzx57rx5bfkia6ryd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string139 = /2020host2021\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string140 = /3nvzqyo6l4wkrzumzu5aod7zbosq4ipgf7ifgj3hsvbcr5vcasordvqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string141 = /3pktcrcbmssvrnwe5skburdwe2h3v6ibdnn5kbjqihsg6eu6s6b7ryqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string142 = /3r7zqtidvujbmfhx52sb34u4vwkh66baefmqzlbqpcnwm3krzipy37yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string143 = /3wugtklp46ufx7dnr6j5cd6ate7wnvnivsyvwuni7hqcqt7hm5r72nid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string144 = /3x55o3u2b7cjs54eifja5m3ottxntlubhjzt6k6htp5nrocjmsxxh7ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string145 = /3ytm3d25hfzvbylkxiwyqmpvzys5of7l4pbosm7ol7czlkplgukjq6yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string146 = /47266\@AIRMAIL\.CC/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string147 = /47h4pwve4scndaneljfnxdhzoulgsyfzbgayyonbwztfz74gsdprz5qd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string148 = /54783\@thesecure\.biz/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string149 = /5ntlvn7lmkezscee2vhatjaigkcu2rzj3bwhqaz32snmqc4jha3gcjad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string150 = /6dtxgqam4crv6rr6\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string151 = /6dtxgqam4crv6rr6\.onion\.cab/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string152 = /6dtxgqam4crv6rr6\.onion\.link/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string153 = /6dtxgqam4crv6rr6\.onion\.to/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string154 = /6dtxgqam4crv6rr6\.tor2web\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string155 = /6v4q5w7di74grj2vtmikzgx2tnq5eagyg2cubpcnqrvvee2ijpmprzqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string156 = /6yofnrq7evqrtz3tzi3dkbrdovtywd35lx3iqbc5dyh367nrdh4jgfyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string157 = /7tkffbh3qiumpfjfq77plcorjmfohmbj6nwq5je6herbpya6kmgoafid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string158 = /88828\@PROTONMAIL\.CH/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string159 = /897243728161\@thesecure\.biz/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string160 = /8filesback\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string161 = /a2dbso6dijaqsmut36r6y4nps4cwivmfog5bpzf6uojovce6f3gl36id\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string162 = /aazsbsgya565vlu2c6bzy6yfiebkcbtvvcytvolt33s77xypi7nypxyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string163 = /admin\@cuba\-supp\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string164 = /akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string165 = /akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string166 = "All Your <span>Important Files</span> Have Been Encrypted" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string167 = "All Your Important Files Have Been Encrypted" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string168 = /alphvmmm27o3abo3r2mlmjrpdmzle3rykajqc5xsj7j7ejksbpsa36ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string169 = /aoacugmutagkwctu\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string170 = /aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string171 = /apvc24autvavxuc6\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string172 = /apvc24autvavxuc6\.onion\.cab/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string173 = /apvc24autvavxuc6\.onion\.city/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string174 = /apvc24autvavxuc6\.onion\.to/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string175 = /arvato\@atomsilo\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string176 = /asgardmaster5\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string177 = /Ashley\.Mowat\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string178 = /avaddonbotrxmuyl\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string179 = /avaddongun7rngel\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string180 = /avosjon4pfh3y7ew3jdwz6ofw7lljcxlbk7hcxxmnxlh5kvf2akcqjad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string181 = /avosqxh72b5ia23dl5fgwcpndkctuzqvh2iefk5imp3pi5gfhel5klad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string182 = /basemmnnqwxevlymli5bs36o5ynti55xojzvn246spahniugwkff2pad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string183 = /bastad5huzwkepdixedg2gekg7jk22ato24zyllp6lnjx7wdtyctgvyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string184 = /Bernardocarlos\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string185 = /bianlianlbc5an4kgnay3opdemgcryg2kpfcbgczopmm3dnbz3uaunad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string186 = /bianlivemqbawcco4cx4a672k2fip3guyxudzurfqvdszafam3ofqgqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string187 = /blacksnaketeam\@armormail\.net/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string188 = /blacksnaketeam\@dnmx\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string189 = /blacksnaketeam\@evilmail\.to/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string190 = /blacksnaketeam\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string191 = /blacksnaketeam\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string192 = /blogvl7tjyjvsfthobttze52w36wwiz34hrfcmorgvdzb6hikucb7aqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string193 = /blogxxu75w63ujqarv476otld7cyjkq4yoswzt4ijadkjwvg3vrvd5yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string194 = /bluecrap\@my\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string195 = /brain\.support\@cyberfear\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string196 = /btpsupport\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string197 = /bwjbbpbcihglahwxxusmyy2nxqdc4oqy4rvyhayn4dxhqzji4qi7taid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string198 = /cactus\@mexicomail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string199 = /cactus787835\@proton\.me/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string200 = /cactusbloguuodvqjmnzlwetjlpj6aggc6iocwhuupb47laukux7ckid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string201 = /cartelirsn5l54ehcbalyyqtfb3j7be2rpvf6ujayaf5qqmg3vlwiayd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string202 = /ccpyeuptrlatb2piua4ukhnhi7lrxgerrcrj4p2b5uhbzqm2xgdjaqid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string203 = /chatc46k7dqtvvrgfqjs6vxrwnmudko2ptiqvlb7doqxxqtjc22tsiad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string204 = /cki3klxqycazagx3r5prae3nmfvxmwa34beknr3il4uf76vxd76akqid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string205 = /clientcuworpelkdwecucgvfhp5uz5n7uohsnokndrlhm2zkntyg3had\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string206 = /closetrap\@aol\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string207 = /contirec7nchr45rx6ympez5rjldibnqzh7lsa56lvjvaeywhvoj3wad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string208 = /contirecj4hbzmyzuydyzrvm2c65blmvhoj2cvf25zqj2dwrrqcq5oad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string209 = /contiuevxdgdhn3zl2kubpajtfgqq4ssj2ipv6ujw7fwhggev3rk6hqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string210 = /cryptr3fmuv4di5uiczofjuypopr63x2gltlsvhur2ump4ebru2xd3yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string211 = /cuba_support\@exploit\.im/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string212 = /cuba4ikm4jakjgmkezytyawtdgr2xymvy6nvzgw5cglswg3si76icnqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string213 = /cyberarkrules\@gmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string214 = /d75itpgjjfe2ys2qivqplbvmw3yyx7o5e4ppt2esit2lluhngulz4hqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string215 = /dark24zz36xm4y2phwe7yvnkkkkhxionhfrwp67awpb3r3bdcneivoqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string216 = /davtdavm734bl4hkr3sr4dvfzpdzuzei2zrcor4vte4a3xuok2rxcmyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string217 = /Deanlivermore\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string218 = /Decfile\@cyberfear\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string219 = /DecFile\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string220 = /decrypttozxybarc\.dconnect\.eu/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string221 = /decrypttozxybarc\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string222 = /decrypttozxybarc\.onion\.cab/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string223 = /decrypttozxybarc\.onion\.link/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string224 = /decrypttozxybarc\.onion\.to/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string225 = /decrypttozxybarc\.tor2web\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string226 = /dectokyo\@cock\.li/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string227 = /dectokyo\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string228 = /derdiarikucisv\@gmx\.de/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string229 = /deritim\@proton\.me/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string230 = /dgnh6p5uq234zry7qx7bh73hj5ht3jqisgfet6s7j7uyas5i46xfdkyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string231 = /dlyo7r3n4qy5fzv4645nddjwarj7wjdd6wzckomcyc7akskkxp4glcad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string232 = /dnpscnbaix6nkwvystl3yxglz7nteicqrou3t75tpcc5532cztc46qyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string233 = /Don\'t\sgo\sto\sthe\spolice\sor\sthe\sFBI\sfor\shelp\.\sThey\swon\'t\shelp\syou/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string234 = /e3v6tjarcltwc4hdkn6fxnpkzq42ul7swf5cfqw6jzvic4577vxsxhid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string235 = /ebljej7okwfnx5hdfikqqt2uqehihqv3yns3ziij5clqpklwb3i2cxad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string236 = /ebwexiymbsib4rmw\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string237 = /ellen0xffff\@proton\.me/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string238 = /embargobe3n5okxyzqphpmk3moinoap2snz5k6765mvtkk7hhi544jid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string239 = /et22fibzuzfyzgurm35sttm52qbzvdgzy5qhzy46a3gmkrrht3lec5ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string240 = /evilpr0ton\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string241 = /eviluser\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string242 = /farusbig\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string243 = /fast_decrypt_and_protect\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string244 = /fcjam663uvgid2xbar24kab2vt4hjzsn6o77glh35jscuo567b2mnyqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string245 = /gamol6n6p2p4c3ad7gxmx3ur7wwdwlywebo2azv3vv5qlmjmole2zbyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string246 = /gandcrabmfe6mnef\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string247 = /gunyhng6pabzcurl7ipx2pbmjxpvqnu6mxf2h3vdeenam34inj4ndryd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string248 = /gvka2m4qt5fod2fltkjmdk4gxh5oxemhpgmnmtjptms6fkgfzdd62tad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string249 = /gwisin4yznpdtzq424i3la6oqy5evublod4zbhddzuxcnr34kgfokwad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string250 = /gwvueqclwkz3h7u75cks2wmrwymg3qemfyoyqs7vexkx7lhlteagmsyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string251 = /halielang\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string252 = /Happycat\@cyberfear\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string253 = /help\.blacksnaketeam\@evilmail\.to/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string254 = /helpermail\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string255 = /helpmanager\@airmail\.cc/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string256 = /helpteam\@mail\.ch/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string257 = /HENRY\.PROWSE\@TUTANOTA\.COM/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string258 = /hivecust6vhekztbqgdnkks64ucehqacge3dij3gyrrpdp57zoq3ooqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string259 = /hiveleakdbtnp76ulyhi52eag6c6tyc3xw7ez7iqy6wc34gd2nekazyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string260 = /hpoo4dosa3x4ognfxpqcrjwnsigvslm7kv6hvmhh2yqczaxy3j6qnwad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string261 = /http\:\/\/161\.35\.200\.18/ nocase ascii wide
        // Description: ransomware note from knight ransomware
        // Reference: https://tria.ge/230901-c2fbqacb36
        $string262 = /http\:\/\/knight.{0,1000}\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string263 = /https\:\/\/t\.me\/eightbase/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string264 = /https\:\/\/t\.me\/NovaGroup2023/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string265 = /https\:\/\/t\.me\/ransom_house/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string266 = /hunters33dootzzwybhxyh6xnmumopeoza6u4hkontdqu7awnhmix7ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string267 = /hunters33mmcwww7ek7q5ndahul6nmzmrsumfs6aenicbqon6mxfiqyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string268 = /hunters55atbdusuladzv7vzv6a423bkh6ksl2uftwrxyuarbzlfh7yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string269 = /hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string270 = /hxt254aygrsziejn\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string271 = /iamaduck7\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string272 = "If you do not pay the ransom, we will attack your company again in the future" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string273 = /inbukcc4xk67uzbgkzufdqq3q3ikhwtebqxza5zlfbtzwm2g6usxidqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string274 = /incblog6qu4y4mm4zvw5nrmue6qbwtgjsxpw6b7ixzssu36tsajldoad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string275 = /incblog7vmuq7rktic73r4ha4j757m3ptym37tyvifzp2roedyyzzxid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string276 = /incpaykabjqc2mtdxq6c23nqh4x6m5dkps5fr6vgdkgzp5njssx6qkid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string277 = /incpaysp74dphcbjyvg2eepxnl3tkgt5mq5vd4tnjusoissz342bdnad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string278 = /ithelp07\@decorous\.cyou/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string279 = /ithelp07\@wholeness\.business/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string280 = /iw6v2p3cruy7tqfup3yl4dgt4pfibfa3ai4zgnu5df2q3hus3lm7c7ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string281 = /j\.jasonm\@yandex\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string282 = /j3qxmk6g5sk3zw62i2yhjnwmhm55rfz47fdyfkhaithlpelfjdokdxad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string283 = /jbdg4buq6jd7ed3rd6cynqtq5abttuekjnxqrqyvk4xam5i7ld33jvqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string284 = /jbeg2dct2zhku6c2vwnpxtm2psnjo2xnqvvpoiiwr5hxnc6wrp3uhnad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string285 = /jqlcrn2fsfvxlngdq53rqyrwtwfrulup74xyle54bsvo3l2kgpeeijid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string286 = /jwqpucwiolhmivnqt7qwroezymksxfjsbj6pmg2lnnglqpoe26cwnryd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string287 = /k7kg3jqxang3wh7hnmaiokchk7qoebupfgoik6rha6mjpzwupwtj25yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string288 = /Kirklord1967\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string289 = /knight3xppu263m7g4ag3xlit2qxpryjwueobh7vjdc3zrscqlfu3pqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string290 = /KobieBoho\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string291 = /kuipersupport\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string292 = /l55ysq5qjpin2vq23ul3gc3h62vp4wvenl7ov6fcn65vir7kc7gb5fyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string293 = /landxxeaf2hoyl2jvcwuazypt6imcsbmhb7kx3x33yhparvtmkatpaad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string294 = /lc65fb3wrvox6xlyn4hklwjcojau55diqxxylqs4qsfng23ftzijnxad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string295 = /legalrestore\@airmail\.cc/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string296 = /leonardred1989\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string297 = /LINDA\.HARTLEY\@TUTANOTA\.COM/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string298 = /lirncvjfmdhv6samxvvlohfqx7jklfxoxj7xn3fh7qeabs3taemdsdqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string299 = /lockbit3753ekiocyo5epmpy6klmejchjtzddoekjlnt6mu3qh4de2id\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string300 = /lockbit3g3ohd3katajf6zaehxz4h4cnhmz5t735zpltywhwpc6oy3id\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string301 = /lockbit3olp7oetlc4tl5zydnoluphh7fvdt5oa6arcp2757r7xkutid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string302 = /lockbit435xk3ki62yun7z5nhwz6jyjdp2c64j5vge536if2eny3gtid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string303 = /lockbit4lahhluquhoka3t4spqym2m3dhe66d6lr337glmnlgg2nndad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string304 = /lockbit5eevg7vec4vwwtzgkl4kulap6oxbic2ye4mnmlq6njnpc47qd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string305 = /lockbit6knrauo3qafoksvl742vieqbujxw7rd6ofzdtapjb4rrawqad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string306 = /lockbit74beza5z3e3so7qmjnvlgoemscp7wtp33xo7xv7f7xtlqbkqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string307 = /lockbit75naln4yj44rg6ez6vjmdcrt7up4kxmmmuvilcg4ak3zihxid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string308 = /lockbit7a2g6ve7etbcy6iyizjnuleffz4szgmxaawcbfauluavi5jqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string309 = /lockbit7ouvrsdgtojeoj5hvu6bljqtghitekwpdy3b6y62ixtsu5jqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string310 = /lockbitaa46gwjck2xzmi2xops6x4x3aqn6ez7yntitero2k7ae6yoyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string311 = /lockbitapt2d73krlbewgv27tquljgxr33xbwwsp6rkyieto7u4ncead\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string312 = /lockbitapt2d73krlbewgv27tquljgxr33xbwwsp6rkyieto7u4ncead\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string313 = /lockbitapt2yfbt7lchxejug47kmqvqqxvvjpqkmevv4l3azl3gy6pyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string314 = /lockbitapt2yfbt7lchxejug47kmqvqqxvvjpqkmevv4l3azl3gy6pyd\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string315 = /lockbitapt34kvrip6xojylohhxrwsvpzdffgs5z4pbbsywnzsbdguqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string316 = /lockbitapt34kvrip6xojylohhxrwsvpzdffgs5z4pbbsywnzsbdguqd\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string317 = /lockbitapt5x4zkjbcqmz6frdhecqqgadevyiwqxukksspnlidyvd7qd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string318 = /lockbitapt5x4zkjbcqmz6frdhecqqgadevyiwqxukksspnlidyvd7qd\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string319 = /lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string320 = /lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string321 = /lockbitapt72iw55njgnqpymggskg5yp75ry7rirtdg4m7i42artsbqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string322 = /lockbitapt72iw55njgnqpymggskg5yp75ry7rirtdg4m7i42artsbqd\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string323 = /lockbitaptawjl6udhpd323uehekiyatj6ftcxmkwe5sezs4fqgpjpid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string324 = /lockbitaptawjl6udhpd323uehekiyatj6ftcxmkwe5sezs4fqgpjpid\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string325 = /lockbitaptbdiajqtplcrigzgdjprwugkkut63nbvy2d5r4w2agyekqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string326 = /lockbitaptbdiajqtplcrigzgdjprwugkkut63nbvy2d5r4w2agyekqd\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string327 = /lockbitaptc2iq4atewz2ise62q63wfktyrl4qtwuk5qax262kgtzjqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string328 = /lockbitaptc2iq4atewz2ise62q63wfktyrl4qtwuk5qax262kgtzjqd\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string329 = /lockbitb42tkml3ipianjbs6e33vhcshb7oxm2stubfvdzn3y2yqgbad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string330 = /lockbitcuo23q7qrymbk6dsp2sadltspjvjxgcyp4elbnbr6tcnwq7qd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string331 = /lockbitsap2oaqhcun3syvbqt6n5nzt7fqosc6jdlmsfleu3ka4k2did\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string332 = /lockbitsup4yezcd5enk5unncx3zcy7kw6wllyqmiyhvanjj352jayid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string333 = /lockbitsupa7e3b4pkn4mgkgojrl5iqgx24clbzc4xm7i6jeetsia3qd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string334 = /lockbitsupdwon76nzykzblcplixwts4n4zoecugz2bxabtapqvmzqqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string335 = /lockbitsupn2h6be2cnqpvncyhj4rgmnwn44633hnzzmtxdvjoqlp7yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string336 = /lockbitsupo7vv5vcl3jxpsdviopwvasljqcstym6efhh6oze7c6xjad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string337 = /lockbitsupq3g62dni2f36snrdb4n5qzqvovbtkt5xffw3draxk6gwqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string338 = /lockbitsupqfyacidr6upt6nhhyipujvaablubuevxj6xy3frthvr3yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string339 = /lockbitsupt7nr3fa6e7xyb73lk6bw6rcneqhoyblniiabj4uwvzapqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string340 = /lockbitsupuhswh4izvoucoxsbnotkmgq6durg7kficg6u33zfvq3oyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string341 = /lockbitsupxcjntihbmat4rrh7ktowips2qzywh6zer5r3xafhviyhqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string342 = /lorenzedzyzyjhzxvlcv347n5piltxamo755pzqpozh5l47kj7mxueid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string343 = /lorenzezzwvtk3y24wfph4jpho27grrctqvf6yvld7256rnoz7yg2eid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string344 = /lorenzmlwpzgxq736jzseuterytjueszsvznuibanxomlpkyxk6ksoyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string345 = /luckbit53sdne5yd5vdekadhwnbzjyqlbjkc4g33hs6faphfkvivaeid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string346 = /m232fdxbfmbrcehbrj5iayknxnggf6niqfj6x4iedrgtab4qupzjlaid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string347 = /m6s6axasulxjkhzh\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string348 = /mallox\.resurrection\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string349 = /managersmaers\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string350 = /MARY\.SWANN\@PROTONMAIL\.COM/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string351 = /mastadonster\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string352 = /mazedecrypt\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string353 = /mblogci3rudehaagbryjznltdp33ojwzkq6hn2pckvjq33rycmzczpid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string354 = /mbrlkbtq5jonaqkurjwmxftytyn2ethqvbxfu4rgjbkkknndqwae6byd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string355 = /medusa\.support\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string356 = /medusakxxtp3uo7vusntvubnytaph4d3amxivbggl3hnhpk2nmus34yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string357 = /medusaxko7jxtrojdkxo66j7ck4q5tgktf7uqsqyfry4ebnxlcbkccyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string358 = /mhdehvkomeabau7gsetnsrhkfign4jgnx3wajth5yb5h6kvzbd72wlqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string359 = /Mikedillov1986\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string360 = /MikLYmAklY555\@cock\.li/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string361 = /monti5o7lvyrpyk26lqofnfvajtyqruwatlfaazgm3zskt3xiktudwid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string362 = /moremo123123\@cock\.li/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string363 = /mrv44idagzu47oktcipn6tlll6nzapi6pk3u7ehsucl4hpxon45dl4yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string364 = /ms\.heisenberg\@aol\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string365 = /msv7eaydbdue7x6hos2kzbtwgoi7xmtuddlqgniqghs3qc54wajudwad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string366 = /mybmtbgd7aprdnw2ekxht5qap5daam2wch25coqerrq2zdioanob34ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string367 = /myosbja7hixkkjqihsjh6yvmqplz62gr3r4isctjjtu2vm5jg6hsv2ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string368 = /nbzzb6sa6xuura2z\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string369 = /nevcorps5cvivjf6i2gm4uia7cxng5ploqny2rgrinctazjlnqr2yiyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string370 = /noescapemsqxvizdxyl7f7rmg5cdjwp33pg2wpmiaaibilb4btwzttad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string371 = /noescaperjh3gg6oy7rck57fiefyuzmj7kmvojxgvlmwd5pdzizrb7ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string372 = /noname2j6zkgnt7ftxsjju5tfd3s45s4i3egq5bqtl72kgum4ldc6qyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string373 = /nonamef5njcxkghbjequlibwe5d3t3li5tmyqdyarnrsryopvku76wqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string374 = /nonamehack2023\@gmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string375 = /nonamehack2023\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string376 = /novagroup\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string377 = /npkoxkuygikbkpuf5yxte66um727wmdo2jtpg2djhb2e224i4r25v7ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string378 = /nxx3cy6aee2s53v7v5pxrfv7crfssw7hmgejbj47cv6xuak3bgncllqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string379 = /o6pi3u67zyag73ligtsupin5rjkxpfrbofwoxnhimpgpfttxqu7lsuyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string380 = /ohmva4gbywokzqso\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string381 = /ohmva4gbywokzqso\.onion\.cab/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string382 = /ohmva4gbywokzqso\.tor2web\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string383 = /omx5iqrdbsoitf3q4xexrqw5r5tfw7vp3vl3li3lfo7saabxazshnead\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string384 = /oqwygprskqv65j72\.13gpqd\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string385 = /oqwygprskqv65j72\.1hbdbx\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string386 = /oqwygprskqv65j72\.1jfniy\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string387 = /oqwygprskqv65j72\.1jitcy\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string388 = /oqwygprskqv65j72\.1ldyev\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string389 = /oqwygprskqv65j72\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string390 = /p27dokhpz2n7nvgr\.14udep\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string391 = /p27dokhpz2n7nvgr\.1aweql\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string392 = /p27dokhpz2n7nvgr\.1axzcw\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string393 = /p27dokhpz2n7nvgr\.1hw36d\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string394 = /p27dokhpz2n7nvgr\.1jemdr\.top/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string395 = /p27dokhpz2n7nvgr\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string396 = /p5quu5ujzzswxv4nxyuhgg3fjj2vy2a3zmtcowalkip2temdfadanlyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string397 = /panelqbinglxczi2gqkwderfvgq6bcv5cbjwxrksjtvr5xv7ozh5wqad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string398 = /payorgz3j6hs2gj66nk6omfw65atgmqwzxqbbxnqi3bv2mlwgcirunad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string399 = /pb36hu4spl6cyjdfhing7h3pw6dhpk32ifemawkujj4gp33ejzdq3did\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string400 = /pg3n5bteiatjf6rt7oa4xhzo4sj736rifjmk4gtowxjljuwwdv6mccyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string401 = /pnanlicgxkku2aonwsg2fwid3maycsso7joqnzp66wkfemzdk7ahsdid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string402 = /pod4gkypkd6kykwoht3kioehhpoh4k75ybdfoe6q7hqbphrd77b32jqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string403 = /ppzmaodrgtg7r6zcputdlaqfliubmmjpo4u56l3ayckut3nyvw6dyayd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string404 = /promethw27cbrcot\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string405 = /pts764gt354fder34fsqw45gdfsavadfgsfg\.kraskula\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string406 = /q7wp5u55lhtuafjtsl6lkt24z4wvon2jexfzhzqqfrt3bqnpqboyqoid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string407 = /qd7pcafncosqfqu3ha6fcx4h6sr7tzwagzpcdcnytiw3b6varaeqv5yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string408 = /qkbbaxiuqqcqb5nox4np4qjcniy2q6m7yeluvj7n5i5dn7pgpcwxwfid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string409 = /qmnmrba4s4a3py6z\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string410 = /qn\.support\@cyberfear\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string411 = /qvo5sd7p5yazwbrgioky7rdu4vslxrcaeruhjr7ztn3t2pihp56ewlqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string412 = /ragnar0k\@ctemplar\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string413 = /ragnarjtm25k3w4cy6kvfttfhm24mpynikjt7yll5pvpfo4a7yuzweyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string414 = /ragnarmj3hlykxstyanwtgf33eyacccleg45ctygkuw7dkgysict6xyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string415 = /ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string416 = /ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string417 = /ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string418 = /ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd\.onion\.ly/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string419 = /raworldw32b2qxevn3gp63pvibgixr4v75z62etlptg3u3pmajwra4ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string420 = /rbvuetuneohce3ouxjlbxtimyyxokb4btncxjbo44fbgxqy7tskinwad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string421 = /README\-FILE\-\#COMPUTER\#\-\#TIME\#\.hta/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string422 = /rec_rans\@aol\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string423 = /reltypade1977\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string424 = "Restore your data possible only buying private key from us" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string425 = /rgleaktxuey67yrgspmhvtnrqtgogur35lwdrup4d3igtbm3pupc4lyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string426 = /rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string427 = /rktazuzi7hbln7sy\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string428 = /rnfdsgm6wb6j6su5txkekw4u4y47kp2eatvu7d6xhyn5cs4lt4pdrqqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string429 = /rnsm777cdsjrsdlbs4v5qoeppu3px6sb2igmh53jzrx7ipcrbjz5b2ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string430 = /robertatravels\@mail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string431 = /rook\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string432 = /roselondon\@cock\.li/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string433 = /royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string434 = /s2wk77h653qn54csf4gp52orhem4y72dgxsquxulf255pcymazeepbyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string435 = /santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string436 = /SARAH\.BARRICK\@PROTONMAIL\.COM/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string437 = /sdjf982lkjsdvcjlksaf2kjhlksvvnktyoiasuc92lf\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string438 = /securityRook\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string439 = /secxrosqawaefsio3biv2dmi2c5yunf3t7ilwf54czq3v4bi7w6mbfad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string440 = /servicedigilogos\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string441 = /Shane\.Gilles\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string442 = /SmutnyKobimtochukwu\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string443 = /sonarmsng5vzwqezlvtu2iiwwdn3dxkhotftikhowpfjuzg7p3ca5eid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string444 = /sondr5344ygfweyjbfkw4fhsefv\.heliofetch\.at/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string445 = /sty5r4hhb5oihbq2mwevrofdiqbgesi66rvxr5sr573xgvtuvr4cs5yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string446 = /supp24yy6a66hwszu2piygicgwzdtbwftb76htfj7vnip3getgqnzxid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string447 = /swikipedia\@onionmail\.org/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string448 = /teamchic\@exploit\.im/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string449 = /teamchic\@jabb\.im/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string450 = /teamchic\@yandex\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string451 = /teamchica\@yandex\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string452 = /teilightomemaucd\@gmx\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string453 = /threeam7fj33rv5twe5ll7gcrp3kkyyt6ez5stssixnuwh4v3csxdwqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string454 = /thw73ky2jphtcfrwoze5ddk3wbkc2t24r55guu3agwjchn3g6p755kyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string455 = /torpastezr7464pevuvdjisbvaf4yqi4n7sgz7lkwgqwxznwy5duj4ad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string456 = /tufhackteam\@gmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string457 = /uiredn4njfsa4234bafb32ygjdawfvs\.frascuft\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string458 = /undgrddapc4reaunnrdrmnagvdelqfvmgycuvilgwb5uxm25sxawaoqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string459 = /unlock\@cl\-leaks\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string460 = /unlock\@rsv\-box\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string461 = /unlock\@support\-box\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string462 = /veqlxhq7ub5qze3qy56zx2cig2e6tzsgxdspkubwbayqije6oatma6id\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string463 = /vkvsgl7lhipjirmz6j5ubp3w3bwvxgcdbpi3fsbqngfynetqtw4w5hyd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string464 = /vq\@QyHZx\.xsz/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string465 = /vzzf6yg67cffqndnwg56e4psw45rup45f2mis7bwblg5fs7e5voagsqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string466 = /WayneEvenson\@protonmail\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string467 = /WayneEvenson\@tutanota\.com/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string468 = "WE DESTROYED YOU BACKUPS" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string469 = "WE HACKED YOU" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string470 = "we will continue the process of leaking or selling your documents" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string471 = /weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhkbpqz637f2yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string472 = "Welcome! Your are locked by SenSayQ!" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string473 = /wemo2ysyeq6km2nqhcrz63dkdhez3j25yw2nvn7xba2z4h7v7gyrfgid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string474 = "WHOLE NETWORK HAS BEEN PENETRATED BY Black Hunt" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string475 = "WHOLE NETWORK</span>HAS BEEN PENETRATED BY<span>Black Hunt" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string476 = /wlh3dpptx2gt7nsxcor37a3kiyaiy6qwhdv7o6nl6iuniu5ycze5ydid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string477 = /woqjumaahi662ka26jzxyx7fznbp4kg3bsjar4b52tqkxgm2pylcjlad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string478 = /wtyafjyhwqrgo4a45wdvvwhen3cx4euie73qvlhkhvlrexljoyuklaad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string479 = /wxxp3rny7w3j6gkel56iomdw2ztfzqxlsdw3fyezrnohgh767bau6dqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string480 = /wy35mxvqxff4vufq64v4rrahxltn6ry33hjoogydwti6wbqutjaxrvid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string481 = /xjakumydulag5z65c7kd4agbxfyajpbrj6wfanj3koyhb5asq2x4e7yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string482 = /xlowfznrg4wf7dli\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string483 = /xnsbsjciylsg23zfmrv6ocuyh7ha5zexeouchlr3zsi5suda4arpeyqd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string484 = /xw7au5pnwtl6lozbsudkmyd32n6gnqdngitjdppybudan3x3pjgpmpid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string485 = /yeuajcizwytgmrntijhxphs6wn5txp2prs6rpndafbsapek3zd4ubcid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string486 = "YOU HAVE to CONTACT US using TOR LIVE CHAT" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string487 = "You need to contact us on TOR darknet sites with your personal ID" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string488 = "Your data is stolen and encrypted" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string489 = "your sensitive data, which we Will leak or sell in case of no cooperation" nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string490 = /z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string491 = /z6vidveub2ypo3d3x7omsmcxqwxkkmvn5y3paoufyd2tt4bfbkg33kid\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string492 = /ze677xuzard4lx4iul2yzf5ks4gqqzoulgj5u4n5n4bbbsxjbfr7eayd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string493 = /zeonrefpbompx6rwdqa5hxgtp2cxgfmoymlli3azoanisze33pp3x3yd\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string494 = /zjoxyw5mkacojk5ptn2iprkivg5clow72mjkyk5ttubzxprjjnwapkad\.onion/ nocase ascii wide
        // Description: detection patterns retrieved in ransomware notes archives
        // Reference: https://github.com/threatlabz/ransomware_notes
        $string495 = /znhsupport\@protonmail\.com/ nocase ascii wide

    condition:
        any of them
}
