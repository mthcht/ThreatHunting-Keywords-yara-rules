rule defender_control
{
    meta:
        description = "Detection patterns for the tool 'defender-control' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "defender-control"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string1 = /\/dControl\.exe/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string2 = /\/dControl\.rar/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string3 = /\/Defender\sControl\.zip/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string4 = /\/defender\-control\.git/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string5 = /\/defendercontrol\.zip/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string6 = /\/defenderOff\.rar/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string7 = /\/disable\-defender\.exe/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string8 = /\/enable\-defender\.exe/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string9 = /\\dControl\.exe/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string10 = /\\dControl\.rar/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string11 = /\\Defender\sControl\.zip/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string12 = /\\defender\-control\.sln/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string13 = /\\defendercontrol\.zip/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string14 = /\\defender\-control\\dcontrol\.cpp/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string15 = /\\defenderOff\.rar/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string16 = /\\disable\-defender\.exe/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string17 = /\\dt87xz\\Defender_Settings\.vbs/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string18 = /\\enable\-defender\.exe/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string19 = /\\Root\\InventoryApplicationFile\\defender\-control/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string20 = /\>dControl\sv2\.1\</ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string21 = ">defender-control<" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string22 = "000417262bbfa790d2c3a9f66236dc996b8079c4eb05240301d5de17e5cf6749" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string23 = "089CA7D6-3277-4998-86AF-F6413290A442" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string24 = "1ef6c1a4dfdc39b63bfe650ca81ab89510de6c0d3d7c608ac5be80033e559326" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string25 = "1ef6c1a4dfdc39b63bfe650ca81ab89510de6c0d3d7c608ac5be80033e559326" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string26 = /2015\-2022\swww\.sordum\.org\sAll\sRights\sReserved/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string27 = "2df52ae297704f333af2c7e29544d0c00fcbbccaeb343a8588f9792d482b75a0" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string28 = "435c30dbc7c59f5d013f8088b1f9be04ba003a4d04d7f69d8006bdf190a84bee" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string29 = "45bf0057b3121c6e444b316afafdd802d16083282d1cbfde3cdbf2a9d0915ace" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string30 = "49f487316920c28f546082c345a58fad4bd470507ddc74f34a2515110f193b7d" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string31 = "53bf7ddf48f5231ddaec4e8fe47636f62541226c5bb53374012a68f75c182451" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string32 = "53bf7ddf48f5231ddaec4e8fe47636f62541226c5bb53374012a68f75c182451" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string33 = "57fc37bfab5489b2ace66257d03b23a098ddc80d25b22540e0e5745becc4dbad" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string34 = "688332c4667e6d6e605356fbf205017a7dc9a86731d9fd95beb2562df3bc754b" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string35 = "782ceb859eaa767d4e24ae709d7ab3c0dea3b450c788e04fb2ce4c085e9e8a91" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string36 = "7c2c0aec-7b9d-4104-99fa-1844d609452c" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string37 = "7e94404dc46259916898e5400c4511f885e873dd0fe75357c178053b60b6f7ed" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string38 = "8ba095144dbfff485b4f4db04c338ef687a58306043dad87fe447f219120d1a0" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string39 = "8e25d415c6b4cf0960429c6c9e1ab7720d4dcd637ee15e0e13bcc82d7d7b203b" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string40 = "8e456a357b00fa82bc589a1a13f4dac4ace146083709d6e53106f86095df0f8d" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string41 = "8e9a84da243905685ca77b6ef71841e610b88b7963d4de59f6dcbdd1621ecacd" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string42 = "8e9a84da243905685ca77b6ef71841e610b88b7963d4de59f6dcbdd1621ecacd" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string43 = "909cb2ae71b22db86c4232041f32352ff94db59760593ada386bde5b4dc8901a" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string44 = "92105bc571692ebbab9f00a66c370901439375f98cfca4986f576d9c808dff38" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string45 = "92105bc571692ebbab9f00a66c370901439375f98cfca4986f576d9c808dff38" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string46 = "94c7153749f9d9e3d12da8ff2201927599003808cee82316e9bc632387aeb0cc" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string47 = "962d2a4f2088fbe103c6b38d151689ba100458978ca37a2a9b62047a029f8d33" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string48 = "9d847494b219b153345479919af7ca0e11e253c9f782fafeee8f74c63862c8a2" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string49 = "a0c0ea6786bf9ed2a243e6363409ba76b4f821e64d79e2587501050a46f3e326" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string50 = "af42a17d428c8e9d6f4a6d3393ec268f4d12bbfd01a897d87275482a45c847e9" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string51 = "b6a20cc4035c440aa539a0a8828d4372c9b160002ef9f0e44d9f9e89ed1dfcd0" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string52 = "b8860da17ef3184d74987dd804109669ab503b2faa70438b8072f27b24f6c00a" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string53 = "c1ae1df5425338331c97fc3c3892b01aeaa7d0562369d66d6178a33e6d1f00a0" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string54 = "cd6857024c9a8bbb90a71a2bdaa72e13a0c7be30d288fe81eda8bb98785e5834" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string55 = "d65432a573f67dd33aada2c4dd6ff20d76a7235b2f525979aac588702c4e2364" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string56 = "d87a4da0ba80cee6c60be1a1ebc2c138a79682ca7ad2ef8b91c2035e9a7ecd40" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string57 = "db6749f21079d875bf04af8c1eef3e2e8e2972818273c3032bd8c843f2d72cda" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string58 = /Defender\sControl\sv2\.1\s\-\sAuthor\sby\sBlueLife/ nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string59 = "e5eb2c94e78da85d2a4b0cf973bab87ab3e9d877da6a169d3f2cf9b40eb73a1b" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string60 = "feb09cc39b1520d228e9e9274500b8c229016d6fc8018a2bf19aa9d3601492c5" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string61 = /https\:\/\/drive\.usercontent\.google\.com\/download\?id\=1Up7tr9Zh2e7FVLOdx5J1We3GJLGxEAMO\&export\=download/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string62 = /https\:\/\/www\.sordum\.org\/downloads\/\?st\-defender\-control/ nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string63 = "net stop badrv" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string64 = "net1 stop badrv" nocase ascii wide
        // Description: An open-source windows defender manager. Now you can disable windows defender permanently
        // Reference: https://github.com/pgkt04/defender-control
        $string65 = "pgkt04/defender-control" nocase ascii wide
        // Description: disable windows defender permanently
        // Reference: https://www.sordum.org/9480/defender-control-v2-1/
        $string66 = /tCommand\s\=\s\\"windowsdefender\:\/\/Threatsettings\\".{0,100}CreateObject\(\\"Shell\.Application\\"\)\.ShellExecute\(tCommand\)/ nocase ascii wide
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
