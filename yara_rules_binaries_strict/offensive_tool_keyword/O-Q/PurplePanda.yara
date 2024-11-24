rule PurplePanda
{
    meta:
        description = "Detection patterns for the tool 'PurplePanda' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PurplePanda"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string1 = "carlospolop/PurplePanda" nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string2 = "cd PurplePanda" nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string3 = /\-e\s\-\-enumerate\sgoogle.{0,100}github.{0,100}k8s\s\-\-github\-only\-org\s\-\-k8s\-get\-secret\-values\s\-\-gcp\-get\-secret\-values/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string4 = /purplepanda\.py/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string5 = /purplepanda_config\.py/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string6 = /purplepanda_github\.py/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string7 = "PURPLEPANDA_NEO4J_URL=" nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string8 = /purplepanda_prints\.py/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string9 = "PURPLEPANDA_PWD=" nocase ascii wide
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
