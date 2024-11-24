rule Eventlogedit_evtx__Evolution
{
    meta:
        description = "Detection patterns for the tool 'Eventlogedit-evtx--Evolution' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Eventlogedit-evtx--Evolution"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string1 = /\/Eventlogedit\-evtx\-\-Evolution\.git/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string2 = /\\DeleteRecordbyGetHandle\.cpp/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string3 = /\\DeleteRecordbyGetHandle\.exe/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string4 = /\\DeleteRecordbyGetHandleEx\.cpp/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string5 = /\\DeleteRecordbyTerminateProcess\.cpp/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string6 = /\\DeleteRecordbyTerminateProcess\.exe/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string7 = /\\DeleteRecordbyTerminateProcessEx\.cpp/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string8 = /\\DeleteRecordbyTerminateProcessEx\.exe/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string9 = /\\DeleteRecord\-EvtExportLog\.cpp/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string10 = /\\DeleteRecord\-EvtExportLog\.exe/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string11 = /\\DeleteRecordofFile\.exe/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string12 = /\\DeleteRecordofFileEx\.exe/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string13 = /\\Dll\-EvtExportLog\.cpp/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string14 = /\\Dll\-EvtExportLog\.dll/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string15 = /\\Dll\-rewriting\.cpp/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string16 = /\\Dll\-rewriting\.dll/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string17 = /\\Eventlogedit\-evtx\-\-Evolution\-master\-v1\.1/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string18 = /\\Loader\-EvtExportLog\.cpp/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string19 = /\\Loader\-EvtExportLog\.exe/ nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string20 = "0f6c95ac01cddb461aef1267d60ded9c723aaed9c64cb4507df5cd94e9a1782c" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string21 = "1b1b954cd8593a3d62bfc75524952c11499f269510fd1039a9ec5fa9655b92a7" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string22 = "2257aeb5d063b08394d05286d7d9adfb5850571ea4ffff9ec3d06eb5af75f0e9" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string23 = "319895b096e8bd0d034246c8b7f11b067fc54831451f14d77d04f9b9c50818bc" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string24 = "32221248ee8f748433e89431976294ffa3a62c500e364699cb67fa8471b9c0be" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string25 = "37a95e2ef3089da0c4c732b45cd9aee36b5a0a0709abf4dd1a739a24f8d08c61" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string26 = "3d136d26be0a8879daf18698d9b1e19a4c7a3ef095568a03d4b7a9e0f270034c" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string27 = "3gstudent/Eventlogedit-evtx--Evolution" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string28 = "44c00be47b5171d3edde7649c556efd366d1343665be0610c62941091b081e40" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string29 = "52ff6af0c995ccf66fcd0379f1236578a907768eac72bf659cd7c567c5bb70b2" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string30 = "59875ad922a551d9831d93e54c731399803a814f95a766ef920aef69441564f9" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string31 = "6d4393769a27fd089c9c9f9a52f59e8275397c1c3b8df8ca7c972a3246cb9392" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string32 = "8401c11807fda1838139211517f0aee7ed7198e237b7fd87deceb23e092f1552" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string33 = "8886b069180a096d54b6d6555aa3a5b8c44359eb858a072f6e34943fe40b1fdf" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string34 = "8df104dd0a3a4290bbc33eb8a98a771a8f391120f3014ccb9f2cf496561cccd4" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string35 = "9437e734cd6f37285d60b1d1c33de982d032cd7dea8a0349354c296e9ba46fbc" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string36 = "98b4b0f773391657d762c06de6aa9710e7f56d64a0fd720d1a68e733a8173062" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string37 = "a516e0818b79c222bdc64dcc4f94733ec0678a1dd16a6502d2fc2c722142a5e5" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string38 = "ad953b6731c27ada2c6c7dfd14aca6f46218b962db4272a5c042e4259dacb2e3" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string39 = "b540f94a9f462bc217673faf2d247cb4b9b3eb44ae3307890dc6cda3aa3e5bb2" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string40 = "b7aac417714cff0bd0a03475b7ff00ccdf5480bc463c14d407b9ed8bc8ffcc02" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string41 = "c5f7d585b6535e971c693b57c8a468e5cd9408da09bc91e6dabd8d3b65fe2ba2" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string42 = "c9a67da63c7f2a139df34098d0e74e225b67ed7acc93b18ff23601ce291ab00b" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string43 = "cc7f5f00092e920726e25cf3c47cbf36727e87aba7b4204408b9a44b67816b08" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string44 = "d66e5c655b6ecf6108ebdba4c14b669f8b9dc4c18cfd8eb309878ad936fdc2b9" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string45 = "Delete the eventlog by rewriting the evtx file" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string46 = "Delete the eventlog by using WinAPI EvtExportLog" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string47 = "e090e512d904f56de3f88655cd846ef48fb4d6ed5fedd1f452225c1917f5e352" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string48 = "e3c611553b1544143dd625f75395d57ed0ccc260dc0e6d0204b512a492957050" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string49 = "ea10050aaa6ca06ddceb1e7e47205bf8a59b4f01918dcd7e22cca7aad5613d13" nocase ascii wide
        // Description: 
        // Reference: https://github.com/3gstudent/Eventlogedit-evtx--Evolution
        $string50 = /Eventlogedit\-evtx\-\-Evolution\-master\-v1\.1\.zip/ nocase ascii wide
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
