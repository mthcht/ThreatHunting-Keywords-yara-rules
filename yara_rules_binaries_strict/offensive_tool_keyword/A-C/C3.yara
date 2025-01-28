rule C3
{
    meta:
        description = "Detection patterns for the tool 'C3' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "C3"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string1 = /\/C3\/releases\/download\/.{0,100}\/C3\-/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string2 = /\/C3WebController\.dll/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string3 = /\/ChannelLinter\.exe/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string4 = /\/ChannelLinter_d64\.exe/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string5 = /\/GatewayConsoleExe_d64\.exe/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string6 = /\/NodeRelayConsoleExe_d64\.exe/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string7 = /\\C3WebController\.dll/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string8 = /\\ChannelLinter\.exe/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string9 = /\\ChannelLinter_d64\.exe/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string10 = /\\GatewayConsoleExe_d64\.exe/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string11 = /\\NodeRelayConsoleExe_d64\.exe/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string12 = ">C3WebController<" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string13 = "01c5865909e4e7737cc57397388405fcca18139b3da6845ecef11abbd89f4615" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string14 = "023B2DB0-6DA4-4F0D-988B-4D9BF522DA37" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string15 = "026e9623fd5e6f9ea9adb0dc47ec800db36bbcb5080e8e2bb77d47049c638b16" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string16 = "0da9a753ed44b2716f2434ef664cf46c3ece2b7d5fc1ce810800dd8d23996113" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string17 = "1e7fb9e5dffcf6d3294e99417419221cebf322b760d854c978d9fcdf2994584b" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string18 = "30614c74a863ad156d72f5f00405a87ad098b59fc6e45eaaa1f78cab7222c29c" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string19 = "4adc5ba3d41fb6fd485c85df8bc00fc578280294e5724f34b6d1fbb79d9d1e80" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string20 = "5001938c441ea194bc012da03351a938611309b74c0cf5481dd2de30cb917ae1" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string21 = "53182258-F40E-4104-AFC6-1F327E556E77" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string22 = "55d7fe012433dbdd8a99de24de054be597277f0e7491db62041737e49823f003" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string23 = "5a48220efa4415ca4f849a8b483695de2fac0297f61239afeded512944b929e5" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string24 = "80781550fa32f8a74539450563a7eac0a49ae8d226381e4b496c7c87250a9c0e" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string25 = "8219b80a1dc5a84380f9c5af9e7204e0e2029a173e8ddad57c32a722564832ce" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string26 = "9341205B-AEE0-483B-9A80-975C2084C3AE" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string27 = "946619C2-5959-4C0C-BC7C-1C27D825B042" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string28 = "950c01ef35e9f68b4d8d9d9ea2c642fc6202b44ecabc19591dd7d3f852d02bcf" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string29 = "9e1682246913526e808e837cdb9ffcd209ba4fe43be79c9505c2a98dfef3fb95" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string30 = "acacad2cec4f7abe6f054e451bfe9d2b5e816d74c94f17b8cb38300a1f2851e8" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string31 = "ad58073b97609066a7a55c5b880a23f0986e49e36588ecc68a4f62c29d03b1b1" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string32 = "b692e1272116e31f390f6b36c96a7912ed58f56958bab07db888049f5b65f111" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string33 = "B7C64002-5002-410F-868C-826073AFA924" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string34 = "BC9BC3C3-4FBC-4F36-866C-AC2B4758BEBE" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string35 = "bd8c697efa72709e6f0901cf7f8d570d670c8da9de6af0259ab419f2c55a17c4" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string36 = /C\:\\Temp\\C3Store/ nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string37 = "D00C849B-4FA5-4E84-B9EF-B1C8C338647A" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string38 = "d3c6d1e4ca184e35b872d8e376f74229db95aa4d40b99def7706263e8612ba09" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string39 = "e0c11846a94a3d0f93fa381c38677902b6727bc150944b643c52b51f171787fb" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string40 = "e6908a1213c11347794011b5d126561d39408d3e9e919f1a719135a6221813b9" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string41 = "ebe64c00a953cf3b93b69b2b1b275b9bc97fb70a85713bfc1df6fb1d15e4c938" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string42 = "F2EC73D1-D533-4EE4-955A-A62E306472CC" nocase ascii wide
        // Description: Framework designed for red teams to create and manage custom C2 (Command and Control) channels. Unlike traditional C2 frameworks that rely on typical communication methods like HTTP/S DNS or TCP -  C3 allows for the creation of non-traditional and esoteric C2 channels using platforms like Slack Dropbox GitHub OneDrive and more.
        // Reference: https://github.com/WithSecureLabs/C3
        $string43 = "http://localhost:52935" nocase ascii wide
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
