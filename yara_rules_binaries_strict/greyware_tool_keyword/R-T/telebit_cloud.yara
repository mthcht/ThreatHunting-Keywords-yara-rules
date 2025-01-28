rule telebit_cloud
{
    meta:
        description = "Detection patterns for the tool 'telebit.cloud' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "telebit.cloud"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string1 = /\.config\/telebit\/telebitd\.yml/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string2 = /\/cloud\.telebit\.remote\.plist/
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string3 = "/opt/telebit"
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string4 = "/telebit http "
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string5 = /\/telebit\.js\.git/
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string6 = /\/telebit\.service/
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string7 = "/telebit/var/log/"
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string8 = /\/telebit\-remote\.js/
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string9 = /bin\/telebit\.js/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string10 = /cloud\.telebit\.remot/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string11 = /https\:\/\/.{0,100}\.telebit\.io/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string12 = /https\:\/\/get\.telebit\.io/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string13 = "install -g telebit" nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string14 = /netcat\s.{0,100}\.telebit\.io/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string15 = /ssh\s\-o\s.{0,100}\.telebit\.io/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string16 = /ssh.{0,100}\.telebit\.cloud/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string17 = "telebit ssh auto" nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string18 = "telebit tcp " nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string19 = "--user-unit=telebit" nocase ascii wide
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
