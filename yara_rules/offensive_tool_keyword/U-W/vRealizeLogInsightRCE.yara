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
        $string1 = /.{0,1000}\s\-\-payload_file\s.{0,1000}\s\-\-payload_path.{0,1000}/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string2 = /.{0,1000}\/horizon3ai\/.{0,1000}/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string3 = /.{0,1000}Downloading\s.{0,1000}\/.{0,1000}\.tar\sto\s\/tmp\/.{0,1000}\.pak.{0,1000}/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string4 = /.{0,1000}loginsight\.thrift.{0,1000}/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string5 = /.{0,1000}VMSA\-2023\-0001\.py.{0,1000}/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string6 = /.{0,1000}VMware\-vRealize\-Log\-Insight\.cert.{0,1000}/ nocase ascii wide
        // Description: POC for VMSA-2023-0001 affecting VMware vRealize Log Insight which includes the following CVEs: VMware vRealize Log Insight Directory Traversal Vulnerability (CVE-2022-31706) VMware vRealize Log Insight broken access control Vulnerability (CVE-2022-31704) VMware vRealize Log Insight contains an Information Disclosure Vulnerability (CVE-2022-31711)
        // Reference: https://github.com/horizon3ai/vRealizeLogInsightRCE
        $string7 = /.{0,1000}vRealizeLogInsightRCE.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
