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
        $string1 = /.{0,1000}carlospolop\/PurplePanda.{0,1000}/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string2 = /.{0,1000}cd\sPurplePanda.{0,1000}/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string3 = /.{0,1000}\-e\s\-\-enumerate\sgoogle.{0,1000}github.{0,1000}k8s\s\-\-github\-only\-org\s\-\-k8s\-get\-secret\-values\s\-\-gcp\-get\-secret\-values.{0,1000}/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string4 = /.{0,1000}purplepanda\.py.{0,1000}/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string5 = /.{0,1000}purplepanda_config\.py.{0,1000}/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string6 = /.{0,1000}purplepanda_github\.py.{0,1000}/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string7 = /.{0,1000}PURPLEPANDA_NEO4J_URL\=.{0,1000}/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string8 = /.{0,1000}purplepanda_prints\.py.{0,1000}/ nocase ascii wide
        // Description: This tool fetches resources from different cloud/saas applications focusing on permissions in order to identify privilege escalation paths and dangerous permissions in the cloud/saas configurations. Note that PurplePanda searches both privileges escalation paths within a platform and across platforms.
        // Reference: https://github.com/carlospolop/PurplePanda
        $string9 = /.{0,1000}PURPLEPANDA_PWD\=.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
