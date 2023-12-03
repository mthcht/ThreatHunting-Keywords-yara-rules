rule cloudsploit
{
    meta:
        description = "Detection patterns for the tool 'cloudsploit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloudsploit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts including: Amazon Web Services (AWS) - Microsoft Azure - Google Cloud Platform (GCP) - Oracle Cloud Infrastructure (OCI) and GitHub. These scripts are designed to return a series of potential misconfigurations and security risks.
        // Reference: https://github.com/aquasecurity/cloudsploit
        $string1 = /.{0,1000}\scloudsploit.{0,1000}/ nocase ascii wide
        // Description: CloudSploit by Aqua - Cloud Security Scans
        // Reference: https://github.com/aquasecurity/cloudsploit
        $string2 = /.{0,1000}\/aquasecurity\/cloudsploit.{0,1000}/ nocase ascii wide
        // Description: CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts including: Amazon Web Services (AWS) - Microsoft Azure - Google Cloud Platform (GCP) - Oracle Cloud Infrastructure (OCI) and GitHub. These scripts are designed to return a series of potential misconfigurations and security risks.
        // Reference: https://github.com/aquasecurity/cloudsploit
        $string3 = /.{0,1000}\/cloudsploit\.git.{0,1000}/ nocase ascii wide
        // Description: CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts including: Amazon Web Services (AWS) - Microsoft Azure - Google Cloud Platform (GCP) - Oracle Cloud Infrastructure (OCI) and GitHub. These scripts are designed to return a series of potential misconfigurations and security risks.
        // Reference: https://github.com/aquasecurity/cloudsploit
        $string4 = /.{0,1000}cloudsploit\s.{0,1000}/ nocase ascii wide
        // Description: CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts including: Amazon Web Services (AWS) - Microsoft Azure - Google Cloud Platform (GCP) - Oracle Cloud Infrastructure (OCI) and GitHub. These scripts are designed to return a series of potential misconfigurations and security risks.
        // Reference: https://github.com/aquasecurity/cloudsploit
        $string5 = /.{0,1000}cloudsploit.{0,1000}cloudtrail.{0,1000}/ nocase ascii wide
        // Description: CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts including: Amazon Web Services (AWS) - Microsoft Azure - Google Cloud Platform (GCP) - Oracle Cloud Infrastructure (OCI) and GitHub. These scripts are designed to return a series of potential misconfigurations and security risks.
        // Reference: https://github.com/aquasecurity/cloudsploit
        $string6 = /.{0,1000}cloudsploit\/index\.js.{0,1000}/ nocase ascii wide
        // Description: CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts including: Amazon Web Services (AWS) - Microsoft Azure - Google Cloud Platform (GCP) - Oracle Cloud Infrastructure (OCI) and GitHub. These scripts are designed to return a series of potential misconfigurations and security risks.
        // Reference: https://github.com/aquasecurity/cloudsploit
        $string7 = /.{0,1000}cloudsploit\/scans.{0,1000}/ nocase ascii wide
        // Description: CloudSploit by Aqua is an open-source project designed to allow detection of security risks in cloud infrastructure accounts including: Amazon Web Services (AWS) - Microsoft Azure - Google Cloud Platform (GCP) - Oracle Cloud Infrastructure (OCI) and GitHub. These scripts are designed to return a series of potential misconfigurations and security risks.
        // Reference: https://github.com/aquasecurity/cloudsploit
        $string8 = /.{0,1000}CloudSploitSupplemental.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
