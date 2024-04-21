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
        $string2 = /\/cloud\.telebit\.remote\.plist/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string3 = /\/opt\/telebit/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string4 = /\/telebit\shttp\s/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string5 = /\/telebit\.js\.git/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string6 = /\/telebit\.service/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string7 = /\/telebit\/var\/log\// nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string8 = /\/telebit\-remote\.js/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string9 = /bin\/telebit\.js/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string10 = /cloud\.telebit\.remot/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string11 = /https\:\/\/.{0,1000}\.telebit\.io/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string12 = /https\:\/\/get\.telebit\.io/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string13 = /install\s\-g\stelebit/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string14 = /netcat\s.{0,1000}\.telebit\.io/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string15 = /ssh\s\-o\s.{0,1000}\.telebit\.io/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string16 = /ssh.{0,1000}\.telebit\.cloud/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string17 = /telebit\sssh\sauto/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string18 = /telebit\stcp\s/ nocase ascii wide
        // Description: Access your devices - Share your stuff (shell from telebit.cloud)
        // Reference: https://telebit.cloud/
        $string19 = /\-\-user\-unit\=telebit/ nocase ascii wide

    condition:
        any of them
}
