rule TotalRecall
{
    meta:
        description = "Detection patterns for the tool 'TotalRecall' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TotalRecall"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string1 = /\sRecall\sfolder\sfound\:\s/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string2 = /\s\-\-search\spassword\s\-\-from_date\s.{0,1000}\s\-\-to_date\s/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string3 = /\stotalrecall\.py/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string4 = /\sWindows\sRecall\sfeature\sfound\.\sDo\syou\swant\sto\sproceed\swith\sthe\sextraction\?/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string5 = /\sWindows\sRecall\sfeature\snot\sfound\.\sNothing\sto\sextract/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string6 = /\/TotalRecall\.git/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string7 = /\/totalrecall\.py/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string8 = /\/TotalRecall\.txt/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string9 = /\\2024\-.{0,1000}_Recall_Extraction\\/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string10 = /\\2025\-.{0,1000}_Recall_Extraction\\/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string11 = /\\totalrecall\.py/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string12 = /\\TotalRecall\.txt/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string13 = /\\TotalRecall\\.{0,1000}_Recall_Extraction/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string14 = /353f18e314f024ceea013bd97c140e09fd4ac715bf9ac7c965d0b89845dffcf0/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string15 = /C\:\\\\Users\\\\\{username\}\\\\AppData\\\\Local\\\\CoreAIPlatform\.00\\\\UKP/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string16 = /extraction_folder.{0,1000}TotalRecall\.txt/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string17 = /SELECT\sWindowTitle\,\sTimeStamp\,\sImageToken\s.{0,1000}FROM\sWindowCapture/ nocase ascii wide
        // Description: extracts and displays data from the Recall feature in Windows 11
        // Reference: https://github.com/xaitax/TotalRecall
        $string18 = /xaitax\/TotalRecall/ nocase ascii wide

    condition:
        any of them
}
