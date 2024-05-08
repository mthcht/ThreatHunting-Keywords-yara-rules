rule AMSITrigger
{
    meta:
        description = "Detection patterns for the tool 'AMSITrigger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "AMSITrigger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string1 = /\/AMSITrigger\.git/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string2 = /\\AmsiTrigger\.csproj/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string3 = /\\AmsiTrigger\.sln/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string4 = /\\AMSITrigger\\/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string5 = /\\AMSITrigger\-master/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string6 = /056a00cd961e5d38f464d6a15393c92f3f0cef668e396f9595822e7147b4c25e/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string7 = /0aa6a04c0e8bb0022ccbe0c6f2bf6bc1806c59ffffae3981ae083e49e78573b7/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string8 = /453c7fcdf6fdf446f846057eb2cd90b495caaf442aa07dbeb9655482809fef43/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string9 = /66c00239681d0f5822544fa18f461864df248a0dc5a76c4a3f981dac5af89162/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string10 = /7864978aad22ff10f75864376b0e57d7ec3ba8bd84e663c2c650f5fc45a9b388/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string11 = /8BAAEFF6\-1840\-4430\-AA05\-47F2877E3235/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string12 = /971f7d595c07fa302de6843e85ae22c771bc23a790f4092b5e6cd62fac985ab0/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string13 = /AmsiTrigger\.exe/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string14 = /AmsiTrigger_x64\.exe/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string15 = /AmsiTrigger_x86\.exe/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string16 = /assembly\sAMSITrigger\s/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string17 = /ca081dfda125f3b14589e205288777bdc209941e50cebb2298262adcd5c76c86/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string18 = /f1bdbea3a5f869e83b52e6284e24d76049a3505492a8b7176cb07f2ad03cbe2b/ nocase ascii wide
        // Description: AMSITrigger will identify all of the malicious strings in a powershell file by repeatedly making calls to AMSI using AMSIScanBuffer - line by line. On receiving an AMSI_RESULT_DETECTED response code the line will then be scrutinised to identify the individual triggers
        // Reference: https://github.com/RythmStick/AMSITrigger
        $string19 = /RythmStick\/AMSITrigger/ nocase ascii wide

    condition:
        any of them
}
