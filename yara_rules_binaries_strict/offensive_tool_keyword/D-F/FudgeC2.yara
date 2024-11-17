rule FudgeC2
{
    meta:
        description = "Detection patterns for the tool 'FudgeC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FudgeC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string1 = /\sFudgeC2\s/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string2 = /\sPSObfucate\.py/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string3 = /\(\(gv\s.{0,100}MDr.{0,100}\)\.NamE\[3\,11\,2\]\s\-join\s\'\'/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string4 = /\/api\/v1\/campaign\/.{0,100}\/implants\// nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string5 = /\/api\/v1\/implants\/.{0,100}\/execute/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string6 = /\/api\/v1\/implants\/.{0,100}\/responses/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string7 = /\/c2_server\/resources/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string8 = /\/campaign\/.{0,100}\/implant\/get_all/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string9 = /\/fudge_c2\.sql/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string10 = /\/FudgeC2/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string11 = /\/implant\/register_cmd/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string12 = /\/PSObfucate\.py/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string13 = /\\FudgeC2/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string14 = /\\PSObfucate\.py/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string15 = /\|\sfOreacH\-obJeCT\s\{\(\s\[Int\]\$_\-As\[ChAr\]\)\s\}\)\)\)\\"\s1\>\s\\Windows\\Temp\\.{0,100}\s2\>\&1/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string16 = /07019d2f4f6839056c0faf4f98e284f05c3f899f511d9766490c93d6a961fb71/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string17 = /20fdeb79608d359d60a1eb6378197f23de9cca8e77e776086335a0cea0c972f2/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string18 = /2ad1fbe554f2568cacd173a5dce1f3f87dc7e2005b1fe1dd73646a8ab9a5d1ad/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string19 = /380250752583ba94bf2f4c2b1fef9d9890615099e600b77f01fa0f15f94e3c1c/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string20 = /40b6cb38fbdefd986159c294c15a9d85f477e8f4ff2c5b2beac4c7db5a9b4772/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string21 = /6ee4bce37718d56dc3171c02415b0163d68d808342e5c0ba15851f6e48e77420/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string22 = /7582aa3ab9f635a0c3ef3522f9922e1628875fef425f81643ea7dd0ca9de68e0/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string23 = /82662ee50b98d617aa8f7859c65bb88030e6a68fe72cf4c7fef5fc94da350046/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string24 = /8a56ab0ff1d36594b9c06968b1aff8c6537dffc8e7695729cc419db4c8364d00/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string25 = /afb4d1a05a4b0b47692debfbe57946caa4bfaa2ba18b121bcfe143bf567186be/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string26 = /b887e2c6fbc2358ddae1a0b5335292faabaf628941a19b018230c0a5195201a0/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string27 = /bob\@moozle\.wtf/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string28 = /c2_server.{0,100}\.py/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string29 = /c2_server\.resources/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string30 = /c55abfcbc2387e66916f27209a8c7ec2066eb3f5787ef72a7aa8945646cc3eba/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string31 = /de91f6c22eb6c8cc6da344665a046253392151bab78bf27196fec5d6d3f55b29/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string32 = /enable_persistence\.py/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string33 = /f121ccc497eca1f3692c9ac8e8be1c1c1a4be250d05f7a23e2f71b8240da1ea5/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string34 = /FudgeC2\./ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string35 = /FudgeC2Persistence/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string36 = /FudgeC2Viewer\.py/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string37 = /get_list_of_implant_text/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string38 = /get_obfucation_string_dict/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string39 = /get_powershell_implant_stager\(/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string40 = /get_powershell_obf_strings\(/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string41 = /gp\s\'HKCU\:\\Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust\sProviders\\\'\)\.State/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string42 = /http\:\/\/127\.0\.0\.1.{0,100}\/nlaksnfaobcaowb/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string43 = /Implant\.ImplantGenerator/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string44 = /import\sEnablePersistence/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string45 = /john\@moozle\.wtf/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string46 = /\-JoiN\'.{0,100}\[StrIng\]\:\:JOIn\(.{0,100}\s\-SPlIt.{0,100}\-sPlit.{0,100}\-SpLiT.{0,100}\-sPlIt.{0,100}\-sPLIt.{0,100}\s\|\sfOreacH\-obJeCT\s\{\(\s\[Int\]\$_\-As\[ChAr\]\)\s\}\)\)\)\\"\s1\>\s\\Windows\\Temp\\/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string47 = /payload_encryption\.py/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string48 = /powershell\.exe\s\-win\shidden\s\-NonI\s\-c\s\(icm\s\-scriptblock\s\(\[scriptblock\]\:\:Create\(\[System\.Text\.Encoding\]/ nocase ascii wide
        // Description: FudgeC2 - a command and control framework designed for team collaboration and post-exploitation activities.
        // Reference: https://github.com/Ziconius/FudgeC2
        $string49 = /Ziconius\/FudgeC2/ nocase ascii wide
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
