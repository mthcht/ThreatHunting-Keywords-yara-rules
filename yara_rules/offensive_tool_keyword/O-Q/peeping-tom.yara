rule peeping_tom
{
    meta:
        description = "Detection patterns for the tool 'peeping-tom' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "peeping-tom"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string1 = /\/peeping\-client\.exe/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string2 = /\/peeping\-tom\.app/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string3 = /\/peeping\-tom\.exe/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string4 = /\/peeping\-tom\.git/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string5 = /\[\!\]\sPlease\ssave\sthis\skey\sas\sit\swill\sbe\srequired\sto\sdecrypt\sthe\skeylogs\sfrom\sthe\starget\!/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string6 = /\[\+\]\sKeylog\srecieved\,\sdata\swritten\sto\skeylog\.txt\!/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string7 = /\[Ngrok\sTunnel\sURL/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string8 = /\\peeping\-client\.exe/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string9 = /\\peeping\-tom\.exe/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string10 = /\\peeping\-tom\-main/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string11 = /\\toms\-server\\keylog\.txt/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string12 = "63ec96c5-075f-4f22-92ec-cf28a2f70737" nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string13 = "71bda8ea-08bc-4ab1-9b40-614b167beb64" nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string14 = "8d352347e622b8ff6babf1a119266f59c1b14a48cebc4cb2cf84c00edd276fe3" nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string15 = /abdullahansari1618\@outlook\.com/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string16 = /API\:\:installHook\(\)\s\-\sWindows\skeyboard\shook\scould\snot\sbe\sinstalled\!/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string17 = /Exfiltrate\:\:exfilLogs\(\)/ nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string18 = "fbe18d97dcbd4ee2b6d3d9457142595613cb86a3f59fc7a54f52731925e5026e" nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string19 = "Nothing was logged into the temp workingKeyLog!" nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string20 = "shehzade/peeping-tom" nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string21 = "Windows keyboard hook installed & log exfiltration timer started" nocase ascii wide
        // Description: Remote keylogger for Windows written in C++
        // Reference: https://github.com/shehzade/peeping-tom
        $string22 = "workingKeyLog has been pushed to key log file!" nocase ascii wide

    condition:
        any of them
}
