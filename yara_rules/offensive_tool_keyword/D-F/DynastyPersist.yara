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
        $string1 = /\sdynasty\.sh/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string2 = /\srce\.php\s\/var/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string3 = /\.\/dynasty\.sh/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string4 = /\/DynastyPersist\.git/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string5 = /\/DynastyPersist\/src\/.{0,1000}\.sh/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string6 = /\/var\/tmp\/\.memory\/diamorphine\.c/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string7 = /\/var\/tmp\/\.memory\/diamorphine\.h/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string8 = "/var/www/html/dynasty_rce"
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string9 = /\[\+\]\s\-\sBashrc\spersistence\sadded\!/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string10 = /\[\+\]\s\-\sConfiguring\s\~\/\.bashrc\sfor\spersistence\s\.\.\.\s/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string11 = /\[\+\]\s\-\sLinux\sheader\s\/\sMessage\sOf\sThe\sDay\sPersistence/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string12 = /\[\+\]\s\-\sRootkit\sConfiguration/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string13 = /\[\+\]\s\-\sRootkit\sconfigured\ssuccessfully/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string14 = /\[\+\]\s\-\sSetting\sup\scronjobs\sfor\spersistence\s\.\.\.\s/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string15 = /\[\+\]\s\-\sSystemd\sRoot\sLevel\sService\ssuccessfully\sconfigued\!/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string16 = /\[\+\]\sSuccess\!\sLD_PRELOAD\shas\sbeen\sadded\!/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string17 = /\\DynastyPersist\\src\\.{0,1000}\.sh/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string18 = "<title>Dynasty Persist</title>"
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string19 = "D Y N A S T Y  - P E R S I S T"
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string20 = /dynasty_rce\/rce\.php/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string21 = /DynastyPersist\-main\.zip/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string22 = /echo\s\\"Nothing\sto\ssee\shere\s\.\.\.\s\\"\s\>\s\/var\/log\/kern\.log/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string23 = /echo\s\'alias\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'\'\s\>\>\s.{0,1000}\/\.bashrc.{0,1000}\s/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string24 = /echo\s\'find\scat\=\/bin\/bash\s\-c\s\'bash\s\-i\s\>\&\s\/dev\/tcp\/.{0,1000}\/.{0,1000}\s0\>\&1\'\'\s\>\>\s.{0,1000}\/\.bashrc.{0,1000}\s/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string25 = "ExecStartPre present! ExecStartPre was modified!"
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string26 = /https\:\/\/github\.com\/m0nad\/Diamorphine/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string27 = "LDPreloadPrivesc"
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string28 = /Made\sby\:\s\@Trevohack\s\|\s\@opabravo\s\|\s\@matheuz/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string29 = /Modified\sby\:\sTrevohack\saka\s.{0,1000}SpaceShuttleIO/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string30 = /php\s\-S\s0\.0\.0\.0\:9056\s\&/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string31 = /pty\.spawn\(\\"\/bin\/sh\\".{0,1000}\s\>\>\s\/etc\/update\-motd\.d\/00\-header/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string32 = /spaceshuttle\.io\.all\@gmail\.com/
        // Description: Linux persistence tool with features like SSH Key Generation - Cronjob Persistence - Custom User with Root - RCE Persistence - LKM/Rootkit- Bashrc Persistence - Systemd Service for Root - LD_PRELOAD Privilege Escalation Config - Backdooring Message of the Day / Header and Modifying an Existing Systemd Service
        // Reference: https://github.com/Trevohack/DynastyPersist
        $string33 = "Trevohack/DynastyPersist"

    condition:
        any of them
}
