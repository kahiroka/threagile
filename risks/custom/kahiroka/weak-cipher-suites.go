package main

import (
	"github.com/threagile/threagile/model"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "weak-cipher-suites",
		Title: "Weak Cipher Suites [Plugin]",
		Description: "Weak cipher suites and vulnerable TLS versions risks might arise.",
		Impact:     "If this risk is unmitigated, network attackers might be able to eavesdrop on the TLS connections.",
		ASVS:       "V9 - Communication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
		Action:     "Use of appropriate cipher suites and the latest TLS version",
		Mitigation: "Disable weak cipher sutes and vulnerable SSL3.0/TLS1.0/TLS1.1 protocols.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Development,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "TLS connections",
		RiskAssessment: "Depending on the confidentiality rating of the transferred data-assets.",
		FalsePositives: "If the appropriate cipher suites and TLS versions are used, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        327,
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
			targetAsset := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
			if isOverTLS {
				if !sourceAsset.OutOfScope || !targetAsset.OutOfScope {
					risks = append(risks, createRisk(dataFlow))
				}
			}
		}
	}
	return risks
}

func createRisk(dataFlow model.CommunicationLink) model.Risk {
	impact := model.MediumImpact
	source := model.ParsedModelRoot.TechnicalAssets[dataFlow.SourceId]
	target := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
	title := "<b>Weak cipher suites and vulnerable TLS versions</b> are used on <b>" + dataFlow.Title + "</b> between <b>" + source.Title + "</b> and <b>" + target.Title + "</b>"
	likelihood := model.Likely
	risk := model.Risk{
		Category:                        CustomRiskRule.Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    target.Id,
		MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{target.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataFlow.Id + "@" + source.Id + "@" + target.Id
	return risk
}
