rule veeam_creds
{
    meta:
        description = "Detection patterns for the tool 'veeam-creds' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "veeam-creds"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string1 = /\$VeaamRegPath.{0,1000}SqlDatabaseName/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string2 = /\$VeaamRegPath.{0,1000}SqlInstanceName/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string3 = /\$VeaamRegPath.{0,1000}SqlServerName/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string4 = /\/veeam\-creds\.git/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string5 = /\\veeam\-creds\\/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string6 = /Invoke\-VeeamGetCreds/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string7 = /sadshade\/veeam\-creds/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string8 = /veeam\-creds\-main/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string9 = /Veeam\-Get\-Creds\.ps1/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string10 = /VeeamGetCreds\.yaml/ nocase ascii wide
        // Description: Collection of scripts to retrieve stored passwords from Veeam Backup
        // Reference: https://github.com/sadshade/veeam-creds
        $string11 = /veeampot\.py/ nocase ascii wide

    condition:
        any of them
}
