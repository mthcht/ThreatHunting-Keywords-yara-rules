rule DynastyPersist
{
    meta:
        description = "Detection patterns for the tool 'DynastyPersist' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DynastyPersist"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string1 = /\sdynasty\.sh/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string2 = /\srce\.php\s\/var/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string3 = /\.\/dynasty\.sh/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string4 = /\/DynastyPersist\.git/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string5 = /\/DynastyPersist\/src\/.{0,100}\.sh/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string6 = /\/var\/tmp\/\.memory\/diamorphine\.c/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string7 = /\/var\/tmp\/\.memory\/diamorphine\.h/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string8 = "/var/www/html/dynasty_rce" nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string9 = /\[\+\]\s\-\sBashrc\spersistence\sadded\!/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string10 = /\[\+\]\s\-\sConfiguring\s\~\/\.bashrc\sfor\spersistence\s\.\.\.\s/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string11 = /\[\+\]\s\-\sLinux\sheader\s\/\sMessage\sOf\sThe\sDay\sPersistence/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string12 = /\[\+\]\s\-\sRootkit\sConfiguration/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string13 = /\[\+\]\s\-\sRootkit\sconfigured\ssuccessfully/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string14 = /\[\+\]\s\-\sSetting\sup\scronjobs\sfor\spersistence\s\.\.\.\s/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string15 = /\[\+\]\s\-\sSystemd\sRoot\sLevel\sService\ssuccessfully\sconfigued\!/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string16 = /\[\+\]\sSuccess\!\sLD_PRELOAD\shas\sbeen\sadded\!/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string17 = /\\DynastyPersist\\src\\.{0,100}\.sh/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string18 = "<title>Dynasty Persist</title>" nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string19 = "D Y N A S T Y  - P E R S I S T" nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string20 = /dynasty_rce\/rce\.php/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string21 = /DynastyPersist\-main\.zip/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string22 = /echo\s\\"Nothing\sto\ssee\shere\s\.\.\.\s\\"\s\>\s\/var\/log\/kern\.log/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string23 = /echo\s\'alias\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1\'\'\s\>\>\s.{0,100}\/\.bashrc.{0,100}\s/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string24 = /echo\s\'find\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,100}\/.{0,100}\s0\>\&1\'\'\s\>\>\s.{0,100}\/\.bashrc.{0,100}\s/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string25 = "ExecStartPre present! ExecStartPre was modified!" nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string26 = /https\:\/\/github\.com\/m0nad\/Diamorphine/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string27 = "LDPreloadPrivesc" nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string28 = /Made\sby\:\s\@Trevohack\s\|\s\@opabravo\s\|\s\@matheuz/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string29 = /Modified\sby\:\sTrevohack\saka\s.{0,100}SpaceShuttleIO/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string30 = /php\s\-S\s0\.0\.0\.0\:9056\s\&/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string31 = /pty\.spawn\(\\"\/bin\/sh\\".{0,100}\s\>\>\s\/etc\/update\-motd\.d\/00\-header/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string32 = /spaceshuttle\.io\.all\@gmail\.com/ nocase ascii wide
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string33 = "Trevohack/DynastyPersist" nocase ascii wide
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
