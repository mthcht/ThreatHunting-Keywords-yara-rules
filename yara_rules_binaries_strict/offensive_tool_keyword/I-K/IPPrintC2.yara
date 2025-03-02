rule IPPrintC2
{
    meta:
        description = "Detection patterns for the tool 'IPPrintC2' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IPPrintC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string1 = /\sIPPrintC2\.ps1/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string2 = "\"IPPrint C2 Server\"" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string3 = /\$C2ExternalIP\s\=\s/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string4 = /\$C2ExternalIP/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string5 = /\$C2Output\@\$date\.pdf/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string6 = /\$EncodedCommandExfil/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string7 = /\$IPPrintC2\s\=\s/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string8 = /\$IPPrintC2/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string9 = /\$IPPrintC2\.DocumentName/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string10 = /\$IPPrintC2\.Print/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string11 = /\(Invoke\-WebRequest\s\-Uri\s\\"https\:\/\/ifconfig\.me\/ip\\"\)\.Content/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string12 = /\/IPPrintC2\.git/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string13 = /\/IPPrintC2\.git/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string14 = /\/IPPrintC2\.ps1/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string15 = /\[System\.Text\.Encoding\]\:\:Unicode\.GetBytes\(\\"\[scriptblock\].{0,100}\$x\=\{\$CommandDoc\}\;.{0,100}\$x\.Invoke\(\)/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string16 = /\\\\DESKTOP\-PRINTINGFUN/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string17 = /\\IPPrintC2\.ps1/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string18 = "49656d058f63398c98cff95a5bbe76a6911e003ddb7baea082a7e7752525d6a6" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string19 = "4c02774a5edb8a559beebcb64833177a893b49fb8eb9bfd2e650155a207c7ba7" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string20 = "6ff59387bfda905c88b75b8f345bca0fd9ea0ab327da28572a4e60c8bf4e1c4d" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string21 = "826c1daf512bcd2152b6328fc55b1ed403ed41fd1a6fc1afa6e35f34e4b9f8bc" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string22 = /Add\-Printer\s\-Name\s\\"http\:\/\/\$server\/\$printername\\"\s\-PortName\s\\"http\:\/\/\$server\/printers\/\$printername\/\.printer\\"/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string23 = /Add\-Printer\s\-Name\s\$PrinterName\s\-DriverName\s\\"Generic\s\/\sText\sOnly\\"\s.{0,100}\s\-PortName/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string24 = /Add\-PrinterPort\s\$C2output/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string25 = /c\:\\temp\\c2\.pdf/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string26 = /C\:\\temp\\c2\.pdf/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string27 = "d222451147be2256c701679975cd45993377032f1d6afff27533bafda10c2afa" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string28 = /DESKTOP\-PRINTINGFUN\\/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string29 = "Diverto/IPPrintC2" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string30 = "Diverto/IPPrintC2" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string31 = "fd52f1cd337f51b76463cc12d6d0c32108a324d6d72d57c852326053ca608495" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string32 = "Invoke-DatatExfiltration" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string33 = "Invoke-DatatExfiltration" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string34 = "Invoke-FileC2Output" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string35 = "Invoke-FileC2Output" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string36 = "Invoke-ReadC2Output" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string37 = "Invoke-ReadC2Output" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string38 = /IPPrintC2\.ps1/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string39 = /IPPrintC2\-main\.zip/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string40 = /ls\s\-r\s\$ExfilDocname/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string41 = /New\-Item\s\$C2Output\s/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string42 = /New\-ScheduledTaskTrigger\s\-AtLogOn\s\-User\s\$env\:username\;Register\-ScheduledTask\s\-TaskName\s\\"Microsoft\sXPS\\"/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string43 = /powershell\s\-enc\s\(\(Get\-PrintJob\sXPS\)\.documentname\s\-join/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string44 = /powershell\s\-w\shidden\s\-NoExit\s\-c\s\{start\-job\s\-s\s\{while\(\$TRUE\)\{powershell\s\-EnC\s\(\(Get\-PrintJob\sXPS\)\.documentname\s\-join\s\'\'\)\;sleep\s60\}/ nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string45 = "Where do you want to store PDF C2 output " nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string46 = "Write-Host -ForegroundColor Yellow \"IPPrint C2 Server\"" nocase ascii wide
        // Description: PoC for using MS Windows printers for persistence / command and control via Internet Printing
        // Reference: https://github.com/Diverto/IPPrintC2
        $string47 = "WwBzAGMAcgBpAHAAdABiAGwAbwBjAGsAXQAkAHgAPQB7AHcAaABvAGEAbQBpACAALwBhAGwAbAA7AGgAbwBzAHQAbgBhAG0AZQB9ADsAJAB4AC4AaQBuAHYAbwBrAGUAKAApAA" nocase ascii wide
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
