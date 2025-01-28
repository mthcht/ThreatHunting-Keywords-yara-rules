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
        $string1 = /\/github\.com.{0,100}\.exe\?raw\=true/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string2 = /\/github\.com\/.{0,100}\/archive\/refs\/tags\/.{0,100}\.zip/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string3 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.7z/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string4 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.apk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string5 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.app/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string6 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.as/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string7 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.asc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string8 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.asp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string9 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.bash/
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string10 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.bat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string11 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.beacon/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string12 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.bin/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string13 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.bpl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string14 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.c/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string15 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.cer/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string16 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.cmd/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string17 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.com/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string18 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.cpp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string19 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.crt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string20 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.cs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string21 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.csh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string22 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.dat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string23 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.dll/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string24 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.docm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string25 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.dos/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string26 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.exe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string27 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.go/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string28 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.gz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string29 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.hta/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string30 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.iso/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string31 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.jar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string32 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.js/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string33 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.lnk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string34 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.log/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string35 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.mac/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string36 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.mam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string37 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.msi/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string38 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.msp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string39 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.nexe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string40 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.nim/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string41 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.otm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string42 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.out/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string43 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.ova/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string44 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.pem/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string45 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.pfx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string46 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.pl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string47 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.plx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string48 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.pm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string49 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.ppk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string50 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.ps1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string51 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.psm1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string52 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.pub/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string53 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.py/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string54 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.pyc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string55 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.pyo/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string56 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.rar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string57 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.raw/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string58 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.reg/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string59 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.rgs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string60 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.RGS/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string61 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.run/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string62 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.scpt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string63 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.script/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string64 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.sct/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string65 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.sh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string66 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.ssh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string67 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.sys/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string68 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.teamserver/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string69 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.temp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string70 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.tgz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string71 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.tmp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string72 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.vb/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string73 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string74 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.vbscript/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string75 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.ws/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string76 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.wsf/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string77 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.wsh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string78 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.X86/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string79 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.X86_64/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string80 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.xlam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string81 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.xlm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string82 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.xlsm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string83 = /\/github\.com\/.{0,100}\/raw\/main\/.{0,100}\.zip/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string84 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.7z/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string85 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.apk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string86 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.bat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string87 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.cmd/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string88 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.com/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string89 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.cpl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string90 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.dll/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string91 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.exe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string92 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.hta/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string93 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.iso/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string94 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.jar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string95 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.lnk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string96 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.msi/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string97 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.pif/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string98 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.ps1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string99 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.py/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string100 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.reg/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string101 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.scr/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string102 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.sh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string103 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string104 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string105 = /\/github\.com\/.{0,100}\/raw\/refs\/heads\/.{0,100}\.zip/ nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string106 = /codeload\.github\.com\// nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string107 = /objects\.githubusercontent\.com\/github\-production\-release\-asset\-/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string108 = /raw\.githubusercontent\.com.{0,100}\.7z/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string109 = /raw\.githubusercontent\.com.{0,100}\.apk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string110 = /raw\.githubusercontent\.com.{0,100}\.app/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string111 = /raw\.githubusercontent\.com.{0,100}\.as/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string112 = /raw\.githubusercontent\.com.{0,100}\.asc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string113 = /raw\.githubusercontent\.com.{0,100}\.asp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string114 = /raw\.githubusercontent\.com.{0,100}\.bash/
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string115 = /raw\.githubusercontent\.com.{0,100}\.bat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string116 = /raw\.githubusercontent\.com.{0,100}\.beacon/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string117 = /raw\.githubusercontent\.com.{0,100}\.bin/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string118 = /raw\.githubusercontent\.com.{0,100}\.bpl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string119 = /raw\.githubusercontent\.com.{0,100}\.c/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string120 = /raw\.githubusercontent\.com.{0,100}\.cer/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string121 = /raw\.githubusercontent\.com.{0,100}\.cmd/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string122 = /raw\.githubusercontent\.com.{0,100}\.com/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string123 = /raw\.githubusercontent\.com.{0,100}\.cpp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string124 = /raw\.githubusercontent\.com.{0,100}\.crt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string125 = /raw\.githubusercontent\.com.{0,100}\.cs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string126 = /raw\.githubusercontent\.com.{0,100}\.csh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string127 = /raw\.githubusercontent\.com.{0,100}\.dat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string128 = /raw\.githubusercontent\.com.{0,100}\.dll/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string129 = /raw\.githubusercontent\.com.{0,100}\.docm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string130 = /raw\.githubusercontent\.com.{0,100}\.dos/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string131 = /raw\.githubusercontent\.com.{0,100}\.exe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string132 = /raw\.githubusercontent\.com.{0,100}\.go/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string133 = /raw\.githubusercontent\.com.{0,100}\.gz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string134 = /raw\.githubusercontent\.com.{0,100}\.hta/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string135 = /raw\.githubusercontent\.com.{0,100}\.iso/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string136 = /raw\.githubusercontent\.com.{0,100}\.jar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string137 = /raw\.githubusercontent\.com.{0,100}\.js/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string138 = /raw\.githubusercontent\.com.{0,100}\.lnk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string139 = /raw\.githubusercontent\.com.{0,100}\.log/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string140 = /raw\.githubusercontent\.com.{0,100}\.mac/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string141 = /raw\.githubusercontent\.com.{0,100}\.mam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string142 = /raw\.githubusercontent\.com.{0,100}\.msi/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string143 = /raw\.githubusercontent\.com.{0,100}\.msp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string144 = /raw\.githubusercontent\.com.{0,100}\.nexe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string145 = /raw\.githubusercontent\.com.{0,100}\.nim/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string146 = /raw\.githubusercontent\.com.{0,100}\.otm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string147 = /raw\.githubusercontent\.com.{0,100}\.out/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string148 = /raw\.githubusercontent\.com.{0,100}\.ova/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string149 = /raw\.githubusercontent\.com.{0,100}\.pem/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string150 = /raw\.githubusercontent\.com.{0,100}\.pfx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string151 = /raw\.githubusercontent\.com.{0,100}\.pl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string152 = /raw\.githubusercontent\.com.{0,100}\.plx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string153 = /raw\.githubusercontent\.com.{0,100}\.pm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string154 = /raw\.githubusercontent\.com.{0,100}\.ppk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string155 = /raw\.githubusercontent\.com.{0,100}\.ps1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string156 = /raw\.githubusercontent\.com.{0,100}\.psm1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string157 = /raw\.githubusercontent\.com.{0,100}\.pub/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string158 = /raw\.githubusercontent\.com.{0,100}\.py/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string159 = /raw\.githubusercontent\.com.{0,100}\.pyc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string160 = /raw\.githubusercontent\.com.{0,100}\.pyo/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string161 = /raw\.githubusercontent\.com.{0,100}\.rar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string162 = /raw\.githubusercontent\.com.{0,100}\.raw/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string163 = /raw\.githubusercontent\.com.{0,100}\.reg/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string164 = /raw\.githubusercontent\.com.{0,100}\.rgs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string165 = /raw\.githubusercontent\.com.{0,100}\.RGS/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string166 = /raw\.githubusercontent\.com.{0,100}\.run/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string167 = /raw\.githubusercontent\.com.{0,100}\.scpt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string168 = /raw\.githubusercontent\.com.{0,100}\.script/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string169 = /raw\.githubusercontent\.com.{0,100}\.sct/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string170 = /raw\.githubusercontent\.com.{0,100}\.sh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string171 = /raw\.githubusercontent\.com.{0,100}\.ssh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string172 = /raw\.githubusercontent\.com.{0,100}\.sys/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string173 = /raw\.githubusercontent\.com.{0,100}\.teamserver/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string174 = /raw\.githubusercontent\.com.{0,100}\.temp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string175 = /raw\.githubusercontent\.com.{0,100}\.tgz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string176 = /raw\.githubusercontent\.com.{0,100}\.tmp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string177 = /raw\.githubusercontent\.com.{0,100}\.vb/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string178 = /raw\.githubusercontent\.com.{0,100}\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string179 = /raw\.githubusercontent\.com.{0,100}\.vbscript/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string180 = /raw\.githubusercontent\.com.{0,100}\.ws/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string181 = /raw\.githubusercontent\.com.{0,100}\.wsf/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string182 = /raw\.githubusercontent\.com.{0,100}\.wsh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string183 = /raw\.githubusercontent\.com.{0,100}\.X86/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string184 = /raw\.githubusercontent\.com.{0,100}\.X86_64/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string185 = /raw\.githubusercontent\.com.{0,100}\.xlam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string186 = /raw\.githubusercontent\.com.{0,100}\.xlm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string187 = /raw\.githubusercontent\.com.{0,100}\.xlsm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string188 = /raw\.githubusercontent\.com.{0,100}\.zip/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
