rule tunnelmole_client
{
    meta:
        description = "Detection patterns for the tool 'tunnelmole-client' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tunnelmole-client"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string1 = /\stunnelmole\.bundle\.js/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string2 = /\.bin\/tmole/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string3 = /\.bin\/tunnelmole/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string4 = /\/bin\/tunnelmole\.js/
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string5 = /\/tunnelmole\.js/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string6 = /\/tunnelmole\-client\.git/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string7 = "/tunnelmole-service" nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string8 = /\/tunnelmole\-service\.git/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string9 = /\\\.tmole\.sh\\/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string10 = /\\tmole\.exe/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string11 = /\\tunnelmole\.bundle\.js/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string12 = "25191b226ad7ef139f81890c531b0c606c5645bbca6f149b3679b06c73e6cddc" nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string13 = "2b4328c30b58ecaf6febe1d7225b543b8886dcb4d8295be5973e6dc36f62c0f2" nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string14 = /dashboard\.tunnelmole\.com/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string15 = /f38fg\.tunnelmole\.net/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string16 = /http\:\/\/.{0,100}\.tunnelmole\.net/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string17 = /https\:\/\/.{0,100}\.tunnelmole\.net/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string18 = /https\:\/\/tunnelmole\.com\/docs/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string19 = /https\:\/\/tunnelmole\.com\/downloads\/tmole\.exe/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string20 = /install\.tunnelmole\.com/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string21 = /node\stunnelmole\.js/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string22 = "npm install -g tunnelmole" nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string23 = /npm\sinstall.{0,100}\stunnelmole/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string24 = /\-\-output\stmole\.exe/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string25 = "robbie-cahill/tunnelmole-client" nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string26 = /service\.tunnelmole\.com/ nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string27 = "tmole - Share your local server with a Public URL" nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string28 = "tmole --set-api-key " nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string29 = "'Tunnelmole Service listening on http port " nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string30 = "Tunnelmole Service listening on websocket port " nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string31 = "tunnelmole/cjs" nocase ascii wide
        // Description: tmole - Share your local server with a Public URL
        // Reference: https://github.com/robbie-cahill/tunnelmole-client/
        $string32 = "TUNNELMOLE_TELEMETRY" nocase ascii wide
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
