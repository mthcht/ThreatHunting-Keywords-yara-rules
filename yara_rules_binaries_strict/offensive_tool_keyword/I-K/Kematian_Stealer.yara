rule Kematian_Stealer
{
    meta:
        description = "Detection patterns for the tool 'Kematian Stealer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Kematian Stealer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string1 = /\sdefender\-exclusions\.ps1/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string2 = /\sencrypthub_steal\.ps1/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string3 = /\sEncryptHub\-WINRAR\-/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string4 = /\$ransomNoteBase64/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string5 = /\/defender\-exclusions\.ps1/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string6 = /\/getChatAdministrators\?chat_id\=1002168553106/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string7 = /\/hvnc\/ngrok\.zip/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github.com/Pirate-Devs/Kematian
        $string8 = /\/kematian\.exe/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string9 = /\/worm\/inject\.ps1/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string10 = /\[STEALER\]\sBypass\sFinished/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string11 = /\\AppData\\Roaming\\Kematian/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string12 = /\\defender\-exclusions\.ps1/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string13 = /\\encrypthub_steal\.ps1/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github.com/Pirate-Devs/Kematian
        $string14 = /\\kematian\.exe/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string15 = /\\Kematian\\.{0,100}Browser\sData/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string16 = /\\Kematian\\.{0,100}Crypto\sWallets/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string17 = /\\Kematian\\.{0,100}Important\sFiles/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string18 = /\\Kematian\\.{0,100}Password\sManagers/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github.com/Pirate-Devs/Kematian
        $string19 = /\\Kematian\-Stealer\\/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string20 = /\\Users\\Public\\ngrok\.exe/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string21 = /\\Users\\Public\\server\.exe/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string22 = /\\WIFIPasswords\.txt/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string23 = /\\WinSCP\-sessions\.txt/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string24 = /078682e4de2e678702911508629fc3e0f293628720e67506340155091ce06ac5/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string25 = /23b63ec6ec2a3d5addcf3d67c8ce01f913f5eaf3a77159606c6d28deff2c8d6e/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string26 = /2dd2927d0f421a78f9289bee0e47449780a13ff7686a9d29c6afb0fec4c22576/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string27 = /4192844c08997d6e198c0511821d0b6cdf8c87aa94cb0b2cd249c114e2c75bb6/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string28 = /54584005fc341d7306b10709e9daf7ab60fcb9c782b7c81aa59c667d41d065bc/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string29 = /7484009227\:AAEvngzrIKFNFdfSqECzWAqbnB5IXk8pjVo/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string30 = /9f946bd0783019a56d2a6de29dd7a2ae1a2b62239396a99eca83b17e4010fc0d/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string31 = /b4ef4d10245cb81ac244e6fb545cc76a5fad1ac79eedbcec69b932765d5f29d8/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string32 = /battle_net_stealer/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github.com/Pirate-Devs/Kematian
        $string33 = /cb4406bc759bd471ac86d80678abd6dcec4934d8db7d92123ebd5960330699cf/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string34 = /cfafc9b2d6cbc65769074bab296c5fbacc676d298f7391a3ff787307eb1cbce0/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string35 = /d08e48fbfffffa54fb689d612cfa21a1a0e906ade2bca23bd12f89ce827bc0df/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string36 = /da8ea1b2c9f697d582cbcf8ef9f61ecdfd4105643cc7da7b026c5333e4b6be58/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string37 = /DecryptWinSCPPassword/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github.com/Pirate-Devs/Kematian
        $string38 = /echo\s\%cmdcmdline\%\s\|\sfind\s\/i\s\\"\%\~f0\\"\>nul\s\|\|\sexit\s\/b\s1/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string39 = /encrypthub_asseq2QSsxzc/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string40 = /epicgames_stealer/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string41 = /\-ExecutionPolicy\sBypass\s\-WindowStyle\sHidden\s\-Command\s\&\s\{taskkill\s\/f\s\/im\smmc\.exe/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string42 = /filezilla_stealer/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string43 = /function\sKematianLoader/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string44 = /Get\-InstalledAV\s/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string45 = /https\:\/\/mainstream\.ngrok\.app\/\?method\=UploadFile\&filename\=/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string46 = /https\:\/\/ratte\.ngrok\.app\/main\/mainer/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string47 = /https\:\/\/t\.me\/encrypthub/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string48 = /https\:\/\/www\.win\-rar\.co\/panel\// nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string49 = /Invoke\-WebRequest\s\-Uri\s\\"http\:\/\/ip\-api\.com\/line\/\?/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string50 = /JGtlbWF0aWFuLlNldFZhbHVlKCRudWxsLCR0cnVlKQ\=\=/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string51 = /KioqUkFOU09NIE5PVEUqKgoKWW91ciBmaWxlcyBoYXZlIGJlZW4gZW5jcnlwdGVkLgoKQWxsIHlvdXIgaW1wb3J0YW50IGZpbGVzLCBpbmNsdWRpbm/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string52 = /livevnc\.ngrok\.app/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string53 = /mshta\.exe\svbscript\:createobject\(\`\\"wscript\.shell\`\\"\)\.run\(\`\\"powershell\s/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github.com/Pirate-Devs/Kematian
        $string54 = /New\-NetFirewallRule\s\-DisplayName\s\\"KematianC2\\"\s/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string55 = /openvpn_stealer/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github.com/Pirate-Devs/Kematian
        $string56 = /Pirate\-Devs\/Kematian/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string57 = /protonvpnstealer/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string58 = /Remove\-Item\s\(Get\-PSreadlineOption\)\.HistorySavePath\s\-Force\s\-ErrorAction\sSilentlyContinue/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string59 = /sap3r\-encrypthub\/encrypthub/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string60 = /Send\-TelegramMessage\s\-message\s/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string61 = /\'Sil\'\+\'ent\'\+\'l\'\+\'yContinu\'\+\'e\'/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string62 = /surfsharkvpnstealer/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string63 = /UmVkIFRlYW1pbmcgYW5kIE9mZmVuc2l2ZSBTZWN1cml0eSAg/ nocase ascii wide
        // Description: Fake WinRar site distributes malware (+stealer +miner +hvnc +ransomware) from GitHub
        // Reference: https://github[.]com/sap3r-encrypthub/encrypthub
        $string64 = /UmVtb3ZlLUl0ZW0gKEdldC1QU3JlYWRsaW5lT3B0aW9uKS5IaXN0b3J5U2F2ZVBhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVl/ nocase ascii wide
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
