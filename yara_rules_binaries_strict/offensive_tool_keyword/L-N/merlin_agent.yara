rule merlin_agent
{
    meta:
        description = "Detection patterns for the tool 'merlin-agent' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "merlin-agent"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string1 = /\slink\ssmb\s.{0,100}\smerlinPipe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string2 = /\s\-o\smerlin\.dll\smerlin\.c\s/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string3 = "/app/bin/merlinAgent"
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string4 = /\/c2endpoint\.php/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string5 = /\/merlinAgent\-.{0,100}\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string6 = /\/merlin\-agent\.git/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string7 = "/merlin-agent/tarball/v" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string8 = "/merlin-agent/v2/cli" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string9 = "/merlin-agent/v2/core" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string10 = "/merlin-agent/zipball/v" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string11 = "/merlinAgent-Linux-x64"
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string12 = "/usr/bin/merlinAgent"
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string13 = /\\\\\.\\pipe\\merlin/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string14 = /\\\\\\\\\.\\\\pipe\\\\merlin/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string15 = /\\merlinAgent\-.{0,100}\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string16 = /\\merlin\-agent\\.{0,100}\.go/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string17 = /\\merlin\-agent\-dll/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string18 = /\\os\\windows\\pkg\\evasion\\evasion/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string19 = /\\services\\p2p\\p2p\.go/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string20 = /127\.0\.0\.1\:7777/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string21 = "21fd88a16e0aa75cc0d7e4f814cbb33e57de921ab5648f94a949318023fdec7d" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string22 = "269ede3b8c442b06d71872f817438e42d9184d58598e11163ff7227c2fe7513e" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string23 = "98a6c8b05256efdf08b252f191b7fefbc76486301fca678a442d2a9ef6393650" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string24 = "9cf730bd8182e8ecc74d6f02dc2eba4dc40d1b50effa30941b522010513baeb6" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string25 = "ad8aa2a15aa507d1d9231c4c5ebaa93501fe32c56d287e83c8f7197d4e15b546" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string26 = /ADDR\s\?\=\s127\.0\.0\.1\:4444/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string27 = "Authenticated returns if the Agent is authenticated to the Merlin server or not" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string28 = "B11F13DC6E6546E134FE8F836C13CCBBD1D8E5120FBD2B40A81E66DFD7C4EBC3" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string29 = "bin/merlinAgent" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string30 = "c36e5e59c3faf245d1cbeb5bf81bdee52eb7d49ff777813e45b33390575072bf" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string31 = "cbf03e162816e6ba6863355f82b4e9e9853f529d11aa95141fc59781496f8e65" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string32 = "d0d03a0ae4722535a0e1d5d0c8385ce42015511e68d960fadef4b4eaf5942feb" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string33 = /DllInstall\sis\sused\swhen\sexecuting\sthe\sMerlin\sagent\swith\sregsvr32\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string34 = /docker\sbuild\s\-t\smerlin\-agent\:.{0,100}\-linux/
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string35 = /docs\.mythic\-c2\.net/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string36 = "fed31f6b45974dfe2f4edc4a180cb44b44caad65e872aa6c656db1d7d3729608" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string37 = "Input Merlin message base:" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string38 = "MAGENT=merlinAgent" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string39 = "merlinAgent-Darwin-x64-"
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string40 = /merlinAgent\-Darwin\-x64\./
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string41 = "merlinAgent-Linux-x64-"
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string42 = /merlinAgent\-Linux\-x64\./
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string43 = "merlinAgent-Windows-x64-" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string44 = /merlinAgent\-Windows\-x64\./ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string45 = /merlinAgent\-Windows\-x64\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string46 = /merlinAgent\-Windows\-x86\.exe/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string47 = /merlin\-c2\.readthedocs\.io/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string48 = /merlinHTTP\.HTTP/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string49 = /merlinHTTP\.JA3/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string50 = /merlinHTTP\.PARROT/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string51 = /merlinHTTP\.WINHTTP/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string52 = /merlinHTTP\.WININET/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string53 = "Ne0nd0g/merlin-agent" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string54 = "r00t0v3rr1d3/merlin" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string55 = "Received Mythic SOCKS task: " nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string56 = /rundll32\smerlin\.dll\,Magic/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string57 = /rundll32\smerlin\.dll\,Merlin/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string58 = /rundll32\smerlin\.dll\,Run/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string59 = /rundll32\.exe.{0,100}\smerlin\.dll\,Magic/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string60 = /rundll32\.exe.{0,100}\smerlin\.dll\,Merlin/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string61 = /rundll32\.exe.{0,100}\smerlin\.dll\,Run/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string62 = /russel\.vantuyl\@gmail\.com/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string63 = /services\/p2p\.Handle\(\)\:\sWrote\sSMB\sfragment\s/ nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string64 = "SetInitialCheckIn updates the time stamp that the Agent first successfully connected to the Merlin server" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string65 = "SetStatusCheckIn updates the last time the Agent successfully communicated with the Merlin server" nocase ascii wide
        // Description: Merlin is a post-exploit Command & Control (C2) tool also known as a Remote Access Tool (RAT)
        // Reference: https://github.com/Ne0nd0g/merlin-agent
        $string66 = "unknown mythic client configuration setting: " nocase ascii wide
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
