rule EmbedInHTML
{
    meta:
        description = "Detection patterns for the tool 'EmbedInHTML' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EmbedInHTML"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string1 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.bat\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string2 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.docm\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string3 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.docx\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string4 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.exe\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string5 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.js\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string6 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.pps\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string7 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.ppsx\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string8 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.ppt\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string9 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.ps1\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string10 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xll\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string11 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xls\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string12 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xlsb\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string13 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xlsm\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string14 = /\.py\s\s\-k\s.{0,100}\s\-f\s.{0,100}\.xlsx\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string15 = /\.py\s\-k\s.{0,100}\s\-f\s.{0,100}\.doc\s\-o\s.{0,100}\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string16 = /\/agent\/stagers\/dropbox\.py/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string17 = /\/EmbedInHTML\.git/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string18 = "/EmbedInHTML/" nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string19 = "Arno0x/EmbedInHTML" nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string20 = /embedInHTML\.html/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string21 = /embedInHTML\.py/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string22 = "EmbedInHTML-master" nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string23 = /\-f\spayloads_examples\/calc\./ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string24 = /payloads_examples.{0,100}calc\.js/ nocase ascii wide
        // Description: What this tool does is taking a file (any type of file). encrypt it. and embed it into an HTML file as ressource. along with an automatic download routine simulating a user clicking on the embedded ressource.
        // Reference: https://github.com/Arno0x/EmbedInHTML
        $string25 = /payloads_examples.{0,100}calc\.xll/ nocase ascii wide
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
