rule vRealizeLogInsightRCE
{
    meta:
        description = "Detection patterns for the tool 'vRealizeLogInsightRCE' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "vRealizeLogInsightRCE"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string1 = /\s\-\-payload_file\s.{0,1000}\s\-\-payload_path/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string2 = /\/horizon3ai\// nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string3 = /Downloading\s.{0,1000}\/.{0,1000}\.tar\sto\s\/tmp\/.{0,1000}\.pak/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string4 = /loginsight\.thrift/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string5 = /VMSA\-2023\-0001\.py/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string6 = /VMware\-vRealize\-Log\-Insight\.cert/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string7 = /vRealizeLogInsightRCE/ nocase ascii wide

    condition:
        any of them
}
