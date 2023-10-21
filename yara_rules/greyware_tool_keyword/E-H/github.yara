rule github
{
    meta:
        description = "Detection patterns for the tool 'github' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "github"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string1 = /\/github\.com.*\.exe\?raw\=true/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string2 = /\/github\.com\/.*\/archive\/refs\/tags\/.*\.zip/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string3 = /\/github\.com\/.*\/raw\/main\/.*\.7z/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string4 = /\/github\.com\/.*\/raw\/main\/.*\.apk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string5 = /\/github\.com\/.*\/raw\/main\/.*\.app/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string6 = /\/github\.com\/.*\/raw\/main\/.*\.as/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string7 = /\/github\.com\/.*\/raw\/main\/.*\.asc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string8 = /\/github\.com\/.*\/raw\/main\/.*\.asp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string9 = /\/github\.com\/.*\/raw\/main\/.*\.bash/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string10 = /\/github\.com\/.*\/raw\/main\/.*\.bat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string11 = /\/github\.com\/.*\/raw\/main\/.*\.beacon/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string12 = /\/github\.com\/.*\/raw\/main\/.*\.bin/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string13 = /\/github\.com\/.*\/raw\/main\/.*\.bpl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string14 = /\/github\.com\/.*\/raw\/main\/.*\.c/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string15 = /\/github\.com\/.*\/raw\/main\/.*\.cer/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string16 = /\/github\.com\/.*\/raw\/main\/.*\.cmd/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string17 = /\/github\.com\/.*\/raw\/main\/.*\.com/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string18 = /\/github\.com\/.*\/raw\/main\/.*\.cpp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string19 = /\/github\.com\/.*\/raw\/main\/.*\.crt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string20 = /\/github\.com\/.*\/raw\/main\/.*\.cs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string21 = /\/github\.com\/.*\/raw\/main\/.*\.csh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string22 = /\/github\.com\/.*\/raw\/main\/.*\.dat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string23 = /\/github\.com\/.*\/raw\/main\/.*\.dll/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string24 = /\/github\.com\/.*\/raw\/main\/.*\.docm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string25 = /\/github\.com\/.*\/raw\/main\/.*\.dos/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string26 = /\/github\.com\/.*\/raw\/main\/.*\.exe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string27 = /\/github\.com\/.*\/raw\/main\/.*\.go/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string28 = /\/github\.com\/.*\/raw\/main\/.*\.gz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string29 = /\/github\.com\/.*\/raw\/main\/.*\.hta/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string30 = /\/github\.com\/.*\/raw\/main\/.*\.iso/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string31 = /\/github\.com\/.*\/raw\/main\/.*\.jar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string32 = /\/github\.com\/.*\/raw\/main\/.*\.js/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string33 = /\/github\.com\/.*\/raw\/main\/.*\.lnk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string34 = /\/github\.com\/.*\/raw\/main\/.*\.log/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string35 = /\/github\.com\/.*\/raw\/main\/.*\.mac/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string36 = /\/github\.com\/.*\/raw\/main\/.*\.mam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string37 = /\/github\.com\/.*\/raw\/main\/.*\.msi/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string38 = /\/github\.com\/.*\/raw\/main\/.*\.msp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string39 = /\/github\.com\/.*\/raw\/main\/.*\.nexe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string40 = /\/github\.com\/.*\/raw\/main\/.*\.nim/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string41 = /\/github\.com\/.*\/raw\/main\/.*\.otm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string42 = /\/github\.com\/.*\/raw\/main\/.*\.out/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string43 = /\/github\.com\/.*\/raw\/main\/.*\.ova/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string44 = /\/github\.com\/.*\/raw\/main\/.*\.pem/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string45 = /\/github\.com\/.*\/raw\/main\/.*\.pfx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string46 = /\/github\.com\/.*\/raw\/main\/.*\.pl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string47 = /\/github\.com\/.*\/raw\/main\/.*\.plx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string48 = /\/github\.com\/.*\/raw\/main\/.*\.pm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string49 = /\/github\.com\/.*\/raw\/main\/.*\.ppk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string50 = /\/github\.com\/.*\/raw\/main\/.*\.ps1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string51 = /\/github\.com\/.*\/raw\/main\/.*\.psm1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string52 = /\/github\.com\/.*\/raw\/main\/.*\.pub/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string53 = /\/github\.com\/.*\/raw\/main\/.*\.py/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string54 = /\/github\.com\/.*\/raw\/main\/.*\.pyc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string55 = /\/github\.com\/.*\/raw\/main\/.*\.pyo/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string56 = /\/github\.com\/.*\/raw\/main\/.*\.rar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string57 = /\/github\.com\/.*\/raw\/main\/.*\.raw/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string58 = /\/github\.com\/.*\/raw\/main\/.*\.reg/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string59 = /\/github\.com\/.*\/raw\/main\/.*\.rgs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string60 = /\/github\.com\/.*\/raw\/main\/.*\.RGS/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string61 = /\/github\.com\/.*\/raw\/main\/.*\.run/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string62 = /\/github\.com\/.*\/raw\/main\/.*\.scpt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string63 = /\/github\.com\/.*\/raw\/main\/.*\.script/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string64 = /\/github\.com\/.*\/raw\/main\/.*\.sct/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string65 = /\/github\.com\/.*\/raw\/main\/.*\.sh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string66 = /\/github\.com\/.*\/raw\/main\/.*\.ssh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string67 = /\/github\.com\/.*\/raw\/main\/.*\.sys/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string68 = /\/github\.com\/.*\/raw\/main\/.*\.teamserver/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string69 = /\/github\.com\/.*\/raw\/main\/.*\.temp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string70 = /\/github\.com\/.*\/raw\/main\/.*\.tgz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string71 = /\/github\.com\/.*\/raw\/main\/.*\.tmp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string72 = /\/github\.com\/.*\/raw\/main\/.*\.vb/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string73 = /\/github\.com\/.*\/raw\/main\/.*\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string74 = /\/github\.com\/.*\/raw\/main\/.*\.vbscript/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string75 = /\/github\.com\/.*\/raw\/main\/.*\.ws/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string76 = /\/github\.com\/.*\/raw\/main\/.*\.wsf/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string77 = /\/github\.com\/.*\/raw\/main\/.*\.wsh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string78 = /\/github\.com\/.*\/raw\/main\/.*\.X86/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string79 = /\/github\.com\/.*\/raw\/main\/.*\.X86_64/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string80 = /\/github\.com\/.*\/raw\/main\/.*\.xlam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string81 = /\/github\.com\/.*\/raw\/main\/.*\.xlm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string82 = /\/github\.com\/.*\/raw\/main\/.*\.xlsm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string83 = /\/github\.com\/.*\/raw\/main\/.*\.zip/ nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string84 = /codeload\.github\.com\// nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string85 = /objects\.githubusercontent\.com\/github\-production\-release\-asset\-/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string86 = /raw\.githubusercontent\.com.*\.7z/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string87 = /raw\.githubusercontent\.com.*\.apk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string88 = /raw\.githubusercontent\.com.*\.app/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string89 = /raw\.githubusercontent\.com.*\.as/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string90 = /raw\.githubusercontent\.com.*\.asc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string91 = /raw\.githubusercontent\.com.*\.asp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string92 = /raw\.githubusercontent\.com.*\.bash/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string93 = /raw\.githubusercontent\.com.*\.bat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string94 = /raw\.githubusercontent\.com.*\.beacon/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string95 = /raw\.githubusercontent\.com.*\.bin/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string96 = /raw\.githubusercontent\.com.*\.bpl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string97 = /raw\.githubusercontent\.com.*\.c/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string98 = /raw\.githubusercontent\.com.*\.cer/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string99 = /raw\.githubusercontent\.com.*\.cmd/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string100 = /raw\.githubusercontent\.com.*\.com/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string101 = /raw\.githubusercontent\.com.*\.cpp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string102 = /raw\.githubusercontent\.com.*\.crt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string103 = /raw\.githubusercontent\.com.*\.cs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string104 = /raw\.githubusercontent\.com.*\.csh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string105 = /raw\.githubusercontent\.com.*\.dat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string106 = /raw\.githubusercontent\.com.*\.dll/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string107 = /raw\.githubusercontent\.com.*\.docm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string108 = /raw\.githubusercontent\.com.*\.dos/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string109 = /raw\.githubusercontent\.com.*\.exe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string110 = /raw\.githubusercontent\.com.*\.go/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string111 = /raw\.githubusercontent\.com.*\.gz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string112 = /raw\.githubusercontent\.com.*\.hta/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string113 = /raw\.githubusercontent\.com.*\.iso/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string114 = /raw\.githubusercontent\.com.*\.jar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string115 = /raw\.githubusercontent\.com.*\.js/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string116 = /raw\.githubusercontent\.com.*\.lnk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string117 = /raw\.githubusercontent\.com.*\.log/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string118 = /raw\.githubusercontent\.com.*\.mac/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string119 = /raw\.githubusercontent\.com.*\.mam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string120 = /raw\.githubusercontent\.com.*\.msi/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string121 = /raw\.githubusercontent\.com.*\.msp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string122 = /raw\.githubusercontent\.com.*\.nexe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string123 = /raw\.githubusercontent\.com.*\.nim/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string124 = /raw\.githubusercontent\.com.*\.otm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string125 = /raw\.githubusercontent\.com.*\.out/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string126 = /raw\.githubusercontent\.com.*\.ova/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string127 = /raw\.githubusercontent\.com.*\.pem/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string128 = /raw\.githubusercontent\.com.*\.pfx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string129 = /raw\.githubusercontent\.com.*\.pl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string130 = /raw\.githubusercontent\.com.*\.plx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string131 = /raw\.githubusercontent\.com.*\.pm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string132 = /raw\.githubusercontent\.com.*\.ppk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string133 = /raw\.githubusercontent\.com.*\.ps1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string134 = /raw\.githubusercontent\.com.*\.psm1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string135 = /raw\.githubusercontent\.com.*\.pub/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string136 = /raw\.githubusercontent\.com.*\.py/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string137 = /raw\.githubusercontent\.com.*\.pyc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string138 = /raw\.githubusercontent\.com.*\.pyo/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string139 = /raw\.githubusercontent\.com.*\.rar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string140 = /raw\.githubusercontent\.com.*\.raw/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string141 = /raw\.githubusercontent\.com.*\.reg/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string142 = /raw\.githubusercontent\.com.*\.rgs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string143 = /raw\.githubusercontent\.com.*\.RGS/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string144 = /raw\.githubusercontent\.com.*\.run/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string145 = /raw\.githubusercontent\.com.*\.scpt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string146 = /raw\.githubusercontent\.com.*\.script/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string147 = /raw\.githubusercontent\.com.*\.sct/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string148 = /raw\.githubusercontent\.com.*\.sh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string149 = /raw\.githubusercontent\.com.*\.ssh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string150 = /raw\.githubusercontent\.com.*\.sys/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string151 = /raw\.githubusercontent\.com.*\.teamserver/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string152 = /raw\.githubusercontent\.com.*\.temp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string153 = /raw\.githubusercontent\.com.*\.tgz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string154 = /raw\.githubusercontent\.com.*\.tmp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string155 = /raw\.githubusercontent\.com.*\.vb/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string156 = /raw\.githubusercontent\.com.*\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string157 = /raw\.githubusercontent\.com.*\.vbscript/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string158 = /raw\.githubusercontent\.com.*\.ws/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string159 = /raw\.githubusercontent\.com.*\.wsf/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string160 = /raw\.githubusercontent\.com.*\.wsh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string161 = /raw\.githubusercontent\.com.*\.X86/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string162 = /raw\.githubusercontent\.com.*\.X86_64/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string163 = /raw\.githubusercontent\.com.*\.xlam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string164 = /raw\.githubusercontent\.com.*\.xlm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string165 = /raw\.githubusercontent\.com.*\.xlsm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string166 = /raw\.githubusercontent\.com.*\.zip/ nocase ascii wide

    condition:
        any of them
}