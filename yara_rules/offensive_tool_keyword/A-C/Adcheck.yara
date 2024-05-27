rule Adcheck
{
    meta:
        description = "Detection patterns for the tool 'Adcheck' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Adcheck"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string1 = /\sADcheck\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string2 = /\s\-\-bloodhound\-file\s/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string3 = /\sGPOBrowser\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string4 = /\sSmallSecretsDump\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string5 = /\/ADcheck\.git/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string6 = /\/ADcheck\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string7 = /\/GPOBrowser\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string8 = /\/SmallSecretsDump\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string9 = /\\ADcheck\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string10 = /\\ADcheck\\Scripts\\activate/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string11 = /\\ADcheck\-main/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string12 = /\\GPOBrowser\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string13 = /\\SmallSecretsDump\.py/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string14 = /29169875afabc27c2b4184d94689aae0955a6d8a7d11788fa3337efd807077ba/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string15 = /admin_can_be_delegated\(self\)/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string16 = /asreproast\(/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string17 = /bdc2c691a61df0926160a728c8419244fa2a1523bf3a3c61a353afa78d80cbfe/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string18 = /CobblePot59\/ADcheck/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string19 = /f4a493d7a8c194fa599d23d6302a5bd7092fe01a60d7803688546b8cb68d8bf4/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string20 = /kerberoast\(self\)/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string21 = /krbtgt_password_age\(self\)/ nocase ascii wide
        // Description: Assess the security of your Active Directory with few or all privileges. This tool offers functionalities similar to PingCastle
        // Reference: https://github.com/CobblePot59/Adcheck
        $string22 = /python\s\-m\svenv\sADcheck/ nocase ascii wide

    condition:
        any of them
}
