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
        $string1 = /\/github\.com.{0,1000}\.exe\?raw\=true/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string2 = /\/github\.com\/.{0,1000}\/archive\/refs\/tags\/.{0,1000}\.zip/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string3 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.7z/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string4 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.apk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string5 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.app/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string6 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.as/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string7 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.asc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string8 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.asp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string9 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bash/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string10 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string11 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.beacon/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string12 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bin/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string13 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.bpl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string14 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.c/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string15 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cer/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string16 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cmd/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string17 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.com/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string18 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cpp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string19 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.crt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string20 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.cs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string21 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.csh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string22 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.dat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string23 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.dll/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string24 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.docm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string25 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.dos/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string26 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.exe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string27 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.go/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string28 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.gz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string29 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.hta/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string30 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.iso/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string31 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.jar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string32 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.js/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string33 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.lnk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string34 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.log/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string35 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.mac/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string36 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.mam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string37 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.msi/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string38 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.msp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string39 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.nexe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string40 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.nim/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string41 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.otm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string42 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.out/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string43 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ova/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string44 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pem/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string45 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pfx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string46 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string47 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.plx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string48 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string49 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ppk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string50 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ps1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string51 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.psm1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string52 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pub/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string53 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.py/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string54 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pyc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string55 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.pyo/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string56 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.rar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string57 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.raw/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string58 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.reg/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string59 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.rgs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string60 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.RGS/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string61 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.run/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string62 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.scpt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string63 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.script/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string64 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.sct/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string65 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.sh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string66 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ssh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string67 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.sys/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string68 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.teamserver/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string69 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.temp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string70 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.tgz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string71 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.tmp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string72 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.vb/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string73 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string74 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.vbscript/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string75 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.ws/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string76 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.wsf/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string77 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.wsh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string78 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.X86/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string79 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.X86_64/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string80 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.xlam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string81 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.xlm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string82 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.xlsm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string83 = /\/github\.com\/.{0,1000}\/raw\/main\/.{0,1000}\.zip/ nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string84 = /codeload\.github\.com\// nocase ascii wide
        // Description: Github executables download initiated - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string85 = /objects\.githubusercontent\.com\/github\-production\-release\-asset\-/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string86 = /raw\.githubusercontent\.com.{0,1000}\.7z/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string87 = /raw\.githubusercontent\.com.{0,1000}\.apk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string88 = /raw\.githubusercontent\.com.{0,1000}\.app/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string89 = /raw\.githubusercontent\.com.{0,1000}\.as/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string90 = /raw\.githubusercontent\.com.{0,1000}\.asc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string91 = /raw\.githubusercontent\.com.{0,1000}\.asp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string92 = /raw\.githubusercontent\.com.{0,1000}\.bash/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string93 = /raw\.githubusercontent\.com.{0,1000}\.bat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string94 = /raw\.githubusercontent\.com.{0,1000}\.beacon/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string95 = /raw\.githubusercontent\.com.{0,1000}\.bin/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string96 = /raw\.githubusercontent\.com.{0,1000}\.bpl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string97 = /raw\.githubusercontent\.com.{0,1000}\.c/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string98 = /raw\.githubusercontent\.com.{0,1000}\.cer/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string99 = /raw\.githubusercontent\.com.{0,1000}\.cmd/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string100 = /raw\.githubusercontent\.com.{0,1000}\.com/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string101 = /raw\.githubusercontent\.com.{0,1000}\.cpp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string102 = /raw\.githubusercontent\.com.{0,1000}\.crt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string103 = /raw\.githubusercontent\.com.{0,1000}\.cs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string104 = /raw\.githubusercontent\.com.{0,1000}\.csh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string105 = /raw\.githubusercontent\.com.{0,1000}\.dat/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string106 = /raw\.githubusercontent\.com.{0,1000}\.dll/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string107 = /raw\.githubusercontent\.com.{0,1000}\.docm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string108 = /raw\.githubusercontent\.com.{0,1000}\.dos/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string109 = /raw\.githubusercontent\.com.{0,1000}\.exe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string110 = /raw\.githubusercontent\.com.{0,1000}\.go/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string111 = /raw\.githubusercontent\.com.{0,1000}\.gz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string112 = /raw\.githubusercontent\.com.{0,1000}\.hta/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string113 = /raw\.githubusercontent\.com.{0,1000}\.iso/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string114 = /raw\.githubusercontent\.com.{0,1000}\.jar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string115 = /raw\.githubusercontent\.com.{0,1000}\.js/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string116 = /raw\.githubusercontent\.com.{0,1000}\.lnk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string117 = /raw\.githubusercontent\.com.{0,1000}\.log/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string118 = /raw\.githubusercontent\.com.{0,1000}\.mac/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string119 = /raw\.githubusercontent\.com.{0,1000}\.mam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string120 = /raw\.githubusercontent\.com.{0,1000}\.msi/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string121 = /raw\.githubusercontent\.com.{0,1000}\.msp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string122 = /raw\.githubusercontent\.com.{0,1000}\.nexe/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string123 = /raw\.githubusercontent\.com.{0,1000}\.nim/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string124 = /raw\.githubusercontent\.com.{0,1000}\.otm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string125 = /raw\.githubusercontent\.com.{0,1000}\.out/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string126 = /raw\.githubusercontent\.com.{0,1000}\.ova/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string127 = /raw\.githubusercontent\.com.{0,1000}\.pem/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string128 = /raw\.githubusercontent\.com.{0,1000}\.pfx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string129 = /raw\.githubusercontent\.com.{0,1000}\.pl/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string130 = /raw\.githubusercontent\.com.{0,1000}\.plx/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string131 = /raw\.githubusercontent\.com.{0,1000}\.pm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string132 = /raw\.githubusercontent\.com.{0,1000}\.ppk/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string133 = /raw\.githubusercontent\.com.{0,1000}\.ps1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string134 = /raw\.githubusercontent\.com.{0,1000}\.psm1/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string135 = /raw\.githubusercontent\.com.{0,1000}\.pub/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string136 = /raw\.githubusercontent\.com.{0,1000}\.py/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string137 = /raw\.githubusercontent\.com.{0,1000}\.pyc/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string138 = /raw\.githubusercontent\.com.{0,1000}\.pyo/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string139 = /raw\.githubusercontent\.com.{0,1000}\.rar/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string140 = /raw\.githubusercontent\.com.{0,1000}\.raw/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string141 = /raw\.githubusercontent\.com.{0,1000}\.reg/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string142 = /raw\.githubusercontent\.com.{0,1000}\.rgs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string143 = /raw\.githubusercontent\.com.{0,1000}\.RGS/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string144 = /raw\.githubusercontent\.com.{0,1000}\.run/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string145 = /raw\.githubusercontent\.com.{0,1000}\.scpt/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string146 = /raw\.githubusercontent\.com.{0,1000}\.script/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string147 = /raw\.githubusercontent\.com.{0,1000}\.sct/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string148 = /raw\.githubusercontent\.com.{0,1000}\.sh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string149 = /raw\.githubusercontent\.com.{0,1000}\.ssh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string150 = /raw\.githubusercontent\.com.{0,1000}\.sys/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string151 = /raw\.githubusercontent\.com.{0,1000}\.teamserver/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string152 = /raw\.githubusercontent\.com.{0,1000}\.temp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string153 = /raw\.githubusercontent\.com.{0,1000}\.tgz/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string154 = /raw\.githubusercontent\.com.{0,1000}\.tmp/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string155 = /raw\.githubusercontent\.com.{0,1000}\.vb/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string156 = /raw\.githubusercontent\.com.{0,1000}\.vbs/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string157 = /raw\.githubusercontent\.com.{0,1000}\.vbscript/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string158 = /raw\.githubusercontent\.com.{0,1000}\.ws/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string159 = /raw\.githubusercontent\.com.{0,1000}\.wsf/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string160 = /raw\.githubusercontent\.com.{0,1000}\.wsh/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string161 = /raw\.githubusercontent\.com.{0,1000}\.X86/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string162 = /raw\.githubusercontent\.com.{0,1000}\.X86_64/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string163 = /raw\.githubusercontent\.com.{0,1000}\.xlam/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string164 = /raw\.githubusercontent\.com.{0,1000}\.xlm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string165 = /raw\.githubusercontent\.com.{0,1000}\.xlsm/ nocase ascii wide
        // Description: Github raw access content - abused by malwares to retrieve payloads
        // Reference: https://github.com/
        $string166 = /raw\.githubusercontent\.com.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}
