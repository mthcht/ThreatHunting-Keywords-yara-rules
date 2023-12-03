rule IMDSpoof
{
    meta:
        description = "Detection patterns for the tool 'IMDSpoof' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IMDSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string1 = /.{0,1000}\/etc\/systemd\/system\/IMDS\.service.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string2 = /.{0,1000}\/IMDSpoof\.git.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string3 = /.{0,1000}grahamhelton\/IMDSpoof.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string4 = /.{0,1000}IMDS\sService\sSpoofing\sEnabled.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string5 = /.{0,1000}IMDSPoof\sHoney\sToken.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string6 = /.{0,1000}IMDSpoof.{0,1000}IMDS\.go.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string7 = /.{0,1000}IMDSpoof\-main.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string8 = /.{0,1000}IQoJb3Jpz2cXpQRkpVX3Uf.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string9 = /.{0,1000}systemctl\sdisable\sIMDS.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string10 = /.{0,1000}systemctl\senable\sIMDS.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string11 = /.{0,1000}systemctl\sstart\sIMDS.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string12 = /.{0,1000}systemctl\sstatus\sIMDS.{0,1000}/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string13 = /.{0,1000}systemctl\sstop\sIMDS.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
