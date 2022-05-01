package main

import (
	"github.com/threagile/threagile/model"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "vulnerable-web-browser",
		Title:       "Vulnerable Web Browser [Plugin]",
		Description: "Vulnerable Same Origin Policy (SOP) and Cross-Origin Resource Sharing (CORS) implementation risks might arise.",
		Impact: "If this risk remains unmitigated, network attackers might be able to steal sensitive information from vistim users.",
		ASVS:       "V4 - Access Control Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html",
		Action:     " Proper SOP/CORS implementation",
		Mitigation: "Properly Implement SOP/CORS mechanisms in the brower component",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Development,
		STRIDE:         model.InformationDisclosure,
		DetectionLogic: "Web browser components",
		RiskAssessment: "The risk rating depends on the confidentiality rating of the data processed on the browser component.",
		FalsePositives: "If a mature browser componen is used, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        284,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{}
}

func (r customRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology == model.Browser {
			likelihood := model.Likely
			risks = append(risks, createRisk(technicalAsset, likelihood))
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, likelihood model.RiskExploitationLikelihood) model.Risk {
	title := "<b>Improper Web Browser</b> found at <b>" + technicalAsset.Title + "</b>"
	impact := model.LowImpact
	risk := model.Risk{
		Category:                        CustomRiskRule.Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		//MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id
	return risk
}
