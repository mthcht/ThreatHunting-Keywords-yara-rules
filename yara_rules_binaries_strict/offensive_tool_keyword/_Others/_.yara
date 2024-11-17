rule _
{
    meta:
        description = "Detection patterns for the tool '_' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "_"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Suspicious extensions files
        // Reference: N/A
        $string1 = /\.doc\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string2 = /\.doc\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string3 = /\.doc\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string4 = /\.doc\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string5 = /\.doc\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string6 = /\.doc\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string7 = /\.doc\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string8 = /\.doc\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string9 = /\.doc\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string10 = /\.docx\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string11 = /\.docx\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string12 = /\.docx\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string13 = /\.docx\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string14 = /\.docx\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string15 = /\.docx\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string16 = /\.docx\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string17 = /\.docx\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string18 = /\.jpg\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string19 = /\.jpg\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string20 = /\.pdf\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string21 = /\.pdf\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string22 = /\.pdf\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string23 = /\.pdf\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string24 = /\.pdf\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string25 = /\.pdf\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string26 = /\.pdf\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string27 = /\.pdf\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string28 = /\.pdf\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string29 = /\.ppt\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string30 = /\.ppt\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string31 = /\.ppt\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string32 = /\.ppt\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string33 = /\.ppt\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string34 = /\.ppt\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string35 = /\.ppt\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string36 = /\.ppt\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string37 = /\.ppt\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string38 = /\.pptx\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string39 = /\.pptx\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string40 = /\.pptx\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string41 = /\.pptx\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string42 = /\.pptx\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string43 = /\.pptx\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string44 = /\.pptx\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string45 = /\.pptx\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string46 = /\.pptx\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string47 = /\.rar\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string48 = /\.rar\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string49 = /\.rtf\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string50 = /\.rtf\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string51 = /\.rtf\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string52 = /\.rtf\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string53 = /\.rtf\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string54 = /\.rtf\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string55 = /\.rtf\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string56 = /\.rtf\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string57 = /\.txt\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string58 = /\.txt\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string59 = /\.txt\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string60 = /\.txt\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string61 = /\.txt\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string62 = /\.txt\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string63 = /\.txt\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string64 = /\.txt\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string65 = /\.txt\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string66 = /\.xls\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string67 = /\.xls\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string68 = /\.xls\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string69 = /\.xls\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string70 = /\.xls\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string71 = /\.xls\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string72 = /\.xls\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string73 = /\.xls\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string74 = /\.xls\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string75 = /\.xlsx\.bat/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string76 = /\.xlsx\.dll/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string77 = /\.xlsx\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string78 = /\.xlsx\.htm/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string79 = /\.xlsx\.iso/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string80 = /\.xlsx\.jar/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string81 = /\.xlsx\.js/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string82 = /\.xlsx\.sfx/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string83 = /\.xlsx\.vbs/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string84 = /\.zip\.exe/ nocase ascii wide
        // Description: Suspicious extensions files
        // Reference: N/A
        $string85 = /\.zip\.iso/ nocase ascii wide
        // Description: keyword observed in multiple backdoor tools
        // Reference: N/A
        $string86 = /\/BackDoor/ nocase ascii wide
        // Description: pentest keyword detection. detect potential pentesters using this keyword in file name. repository or command line
        // Reference: N/A
        $string87 = /\/pentest/ nocase ascii wide
        // Description: scripts in public user folder
        // Reference: N/A
        $string88 = /\:\\users\\public\\.{0,100}\.bat/ nocase ascii wide
        // Description: scripts in public user folder
        // Reference: N/A
        $string89 = /\:\\users\\public\\.{0,100}\.hta/ nocase ascii wide
        // Description: scripts in public user folder
        // Reference: N/A
        $string90 = /\:\\users\\public\\.{0,100}\.ps1/ nocase ascii wide
        // Description: scripts in public user folder
        // Reference: N/A
        $string91 = /\:\\users\\public\\.{0,100}\.vbs/ nocase ascii wide
        // Description: suspicious executable names in suspicious paths related to exploitation tools
        // Reference: N/A
        $string92 = /\\Appdata\\.{0,100}\\aloy64\.exe/ nocase ascii wide
        // Description: suspicious executable names in suspicious paths related to exploitation tools
        // Reference: N/A
        $string93 = /\\Appdata\\.{0,100}\\Beacon\.exe/ nocase ascii wide
        // Description: suspicious executable names in suspicious paths related to exploitation tools
        // Reference: N/A
        $string94 = /\\Appdata\\.{0,100}\\Beacon01\.exe/ nocase ascii wide
        // Description: suspicious executable names in suspicious paths related to exploitation tools
        // Reference: N/A
        $string95 = /\\Appdata\\.{0,100}\\Beacon02\.exe/ nocase ascii wide
        // Description: suspicious executable names in suspicious paths related to exploitation tools
        // Reference: N/A
        $string96 = /\\Appdata\\.{0,100}\\kitty\.exe/ nocase ascii wide
        // Description: known executable in strange location - used by multiple malwares
        // Reference: N/A
        $string97 = /\\Start\sMenu\\Programs\\Startup\\svchost\.exe/ nocase ascii wide
        // Description: dll file in public user folder
        // Reference: https://detect.fyi/rhysida-ransomware-and-the-detection-opportunities-3599e9a02bb2
        $string98 = /c\:\\users\\public\\.{0,100}\.dll/ nocase ascii wide
        // Description: pentest keyword detection. detect potential pentesters using this keyword in file name. repository or command line
        // Reference: N/A
        $string99 = /\-pentest/ nocase ascii wide
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
