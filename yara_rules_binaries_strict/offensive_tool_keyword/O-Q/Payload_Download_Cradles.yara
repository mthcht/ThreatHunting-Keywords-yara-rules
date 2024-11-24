rule Payload_Download_Cradles
{
    meta:
        description = "Detection patterns for the tool 'Payload-Download-Cradles' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Payload-Download-Cradles"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string1 = " /c PoWErSheLl -nopROfi -EXe byPAsS -wiNDOwsTy HIDdEN -cOMMA " nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string2 = /\sCreateObject\(\\"W\\"\+\\"S\\"\+\\"cr\\"\+\\"ip\\"\+\\"t\.\\"\+\\"S\\"\+\\"h\\"\+\\"e\\"\+\\"l\\"\+\\"l\\"\)/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string3 = " danielbohannon/Invoke-CradleCrafter" nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string4 = /\sDownload_Cradles\.hta/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string5 = /\sDownload_Cradles\.ps1/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string6 = " -eXecut byPaSS -Noprof -w H -Co " nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string7 = /\s\-eXecUT\sbyPAss\s\-WINDo\s1\s\-nOpR\s\-coMm\s\\"\\"\&\s\(\(vARiaBlE\s\'.{0,100}mdr.{0,100}\'\)\.Name\[3\,11\,2\]\-JoiN\'\'\)/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string8 = " -eXecUT byPAss -WINDo 1 -nOpR -coMm " nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string9 = /\s\-NoP\s\-w\sHidDen\s\-c\s\$a\=neW\-ObJeCt\snET\.wEbClieNt/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string10 = " -nopROfi -EXe byPAsS -wiNDOwsTy HIDdEN -cOMMA " nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string11 = " -NopROFi -wIN hidd -EXEcutiOnPoLiC BYpAsS  -COm    " nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string12 = " -NoPRofi -WiNdoWSTYL hidd -EXecUTiOnPO BYpASS -cO " nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string13 = " -wINdOwstYL Hi -nop -eXecU BYpAss -COm  " nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string14 = /\$c\.Proxy\.Credentials\=\[Net\.CredentialCache\]\:\:DefaultCredentials\;\`i\`e\`x\s\$c\.downloadstring/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string15 = /\.\\\\"do\`wnLO\`ADS\`TRinG\\/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string16 = /\/Download\:Cradle\.js/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string17 = /\/Download_Cradles\.hta/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string18 = /\/Download_Cradles\.ps1/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string19 = /\/Download\-Cradles\.cmd/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string20 = /\/Payload\-Download\-Cradles\.git/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string21 = /\[System\.Windows\.Forms\.MessageBox\]\:\:Show\(\\"Congratulations\,\sit\slooks\slike\,\syour\sdownload\scradle\sis\sworking/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string22 = /\\Download\:Cradle\.js/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string23 = /\\Download_Cradles\.hta/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string24 = /\\Download_Cradles\.ps1/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string25 = /\\Download\-Cradles\.cmd/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string26 = "1ecb2406b796017446aa92b071d1f26f7fbf2a1a9c61f6b393437500518ec193" nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string27 = "61f31088bc43825c500d7d6f22dd7d259b56dd181c9a59650975bd5e9e91cb25" nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string28 = "a2be75dd7462fbb4753ae380a987351c51d6cd41ba5cc41f08242feeec1df06f" nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string29 = "b7b10a29015b41041519488dc632cd5b0b39358f56d388277d99304917be4a9d" nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string30 = /CreateObject\(\\"\\"W\\"\\"\+\\"\\"S\\"\\"\+\\"\\"cr\\"\\"\+\\"\\"ip\\"\\"\+\\"\\"t\.\\"\\"\+\\"\\"S\\"\\"\+\\"\\"h\\"\\"\+\\"\\"e\\"\\"\+\\"\\"l\\"\\"\+\\"\\"l\\"\\"/ nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string31 = /Download\:Cradle\.js/ nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string32 = /Download_Cradles\./ nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string33 = /Download\-Cradles\.cmd/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string34 = /hidd\s\-EXecUTiOnPO\sBYpASS\s\-cO\s\s\\"i\`EX\s\(\s\s\s\sneW\-o\`BJE\`cT\sN\`ET\.\`weBcl\`IeNT\s\s\s\s\)/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string35 = /https\:\/\/cutt\.ly\/syFzILH/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string36 = /https\:\/\/pastebin\.com\/raw\/88SGrHVh/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string37 = "Invoke-CradleCrafter " nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string38 = "Payload-Download-Cradles" nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string39 = /\'ps\'\+\'\:\'\+\'\/\'\+\'\/\'\+\'cutt\.ly\/syFzIL/ nocase ascii wide
        // Description: download cradles to bypass AV/EPP/EDR in context of download cradle detections
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string40 = "VirtualAlllocEx/Payload-Download-Cradles" nocase ascii wide
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
