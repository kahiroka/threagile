package main

import (
	"github.com/threagile/threagile/model"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "improper-certificate-validation",
		Title: "Improper Certificate Validation [Plugin]",
		Description: "Certificate validation may not be properly implemented.",
		Impact:     "If this risk is unmitigated, network attackers might be able to perform MITM attack against the TLS connections.",
		ASVS:       "V9 - Communication Verification Requirements",
		CheatSheet: "",
		Action:     "Certificate validation",
		Mitigation: "Validate CN/SAN, expiration, revocation and chain of certificates.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Development,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "TLS connections",
		RiskAssessment: "Depending on the confidentiality rating of the transferred data-assets.",
		FalsePositives: "If the appropriate certificate validation is implemented, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        295,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{}
}

func _isOverTLS(dataFlow model.CommunicationLink) bool {
	isOverTLS := dataFlow.Protocol == model.HTTPS || dataFlow.Protocol == model.WSS || dataFlow.Protocol == model.Reverse_proxy_web_protocol_encrypted || dataFlow.Protocol == model.MQTTS ||
		dataFlow.Protocol == model.JDBC_encrypted || dataFlow.Protocol == model.ODBC_encrypted || dataFlow.Protocol == model.SQL_access_protocol_encrypted ||
		dataFlow.Protocol == model.NoSQL_access_protocol_encrypted || dataFlow.Protocol == model.SMTP_encrypted || dataFlow.Protocol == model.POP3_encrypted ||
		dataFlow.Protocol == model.IMAP_encrypted || dataFlow.Protocol == model.FTPS || dataFlow.Protocol == model.LDAPS || dataFlow.Protocol == model.IIOP_encrypted ||
		dataFlow.Protocol == model.JRMP_encrypted || dataFlow.Protocol == model.RTSPS || dataFlow.Protocol == model.RTMPS
	return isOverTLS
}

func (r customRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			isOverTLS := _isOverTLS(dataFlow)
			sourceAsset := model.ParsedModelRoot.TechnicalAssets[dataFlow.SourceId]
			if !technicalAsset.OutOfScope || !sourceAsset.OutOfScope { // sourceAsset needed?
				if isOverTLS {
					risks = append(risks, createRisk(technicalAsset, dataFlow))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, dataFlow model.CommunicationLink) model.Risk {
	impact := model.MediumImpact
	target := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
	title := "<b>Improper certificate validation</b> risk at <b>" + technicalAsset.Title + " via " + dataFlow.Title + "</b> to <b>" + target.Title + "</b>"
	likelihood := model.Likely
	risk := model.Risk{
		Category:                        CustomRiskRule.Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataFlow.Id + "@" + technicalAsset.Id + "@" + target.Id
	return risk
}
