rule curlshell
{
    meta:
        description = "Detection patterns for the tool 'curlshell' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "curlshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string1 = /\scurlshell\.py/
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string2 = /\.py\s.{0,100}0\.0\.0\.0.{0,100}\-\-serve\-forever/
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string3 = /\.py\s.{0,100}\-\-dependabot\-workaround/
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string4 = /\.py\s\-\-certificate\s.{0,100}\.pem\s\-\-private\-key\s.{0,100}\.pem\s\-\-listen\-port\s/
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string5 = /\.py\s\-\-certificate\sfullchain\.pem\s\-\-private\-key\sprivkey\.pem\s\-\-listen\-port\s/
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string6 = /\/curlshell\.git/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string7 = /\/curlshell\.git/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string8 = /\/curlshell\.py/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string9 = /\/curlshell\-main\./ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string10 = "/curlshell-main/" nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string11 = /\\curlshell\.py/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string12 = /\\curlshell\-main/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string13 = /\\curlshell\-main\\/ nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string14 = "b8285e421d702738eab45670ecae439a7228994e7068b04cb51740e47efbfb41" nocase ascii wide
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string15 = "curl https://curlshell"
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string16 = /curlshell\.py/
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string17 = "https://curlshell:"
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string18 = /https\:\/\/curlshell\:.{0,100}\s\|\sbash/
        // Description: reverse shell using curl
        // Reference: https://github.com/irsl/curlshell
        $string19 = "irsl/curlshell"
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
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
