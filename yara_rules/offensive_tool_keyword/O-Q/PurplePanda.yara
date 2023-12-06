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
        $string1 = /carlospolop\/PurplePanda/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string2 = /cd\sPurplePanda/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string3 = /\-e\s\-\-enumerate\sgoogle.{0,1000}github.{0,1000}k8s\s\-\-github\-only\-org\s\-\-k8s\-get\-secret\-values\s\-\-gcp\-get\-secret\-values/ nocase ascii wide
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
        $string7 = /PURPLEPANDA_NEO4J_URL\=/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string8 = /purplepanda_prints\.py/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string9 = /PURPLEPANDA_PWD\=/ nocase ascii wide

    condition:
        any of them
}
