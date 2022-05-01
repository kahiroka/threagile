package main

import (
	"github.com/threagile/threagile/model"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:          "clickjacking",
		Title:       "Clickjacking [Plugin]",
		Description: "For each web application clickjacking risks might arise.",
		Impact: "If this risk remains unmitigated, network attackers might be able to trick victim users into unwanted actions within the web application " +
			"by visiting an attacker controlled web site.",
		ASVS:       "V14.4 - HTTP Security Headers",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
		Action:     "Clickjacking Prevention",
		Mitigation: "Properly set both X-Frame-Options and Content-Security-Policy frame-ancestos.",
		Check:          "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:       model.Development,
		STRIDE:         model.Tampering,
		DetectionLogic: "In-scope web applications",
		RiskAssessment: "The risk rating depends on the integrity rating of the data sent across the communication link.",
		FalsePositives: "If the appropriate headers are configured, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        1021,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{}
}

func (r customRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, id := range model.SortedTechnicalAssetIDs() {
		technicalAsset := model.ParsedModelRoot.TechnicalAssets[id]
		if !technicalAsset.OutOfScope && technicalAsset.Technology.IsWebApplication() {
			incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[id]
			for _, incomingFlow := range incomingFlows {
				sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
				if sourceAsset.Technology == model.Browser {
					risks = append(risks, createRisk(technicalAsset, incomingFlow))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, incomingFlow model.CommunicationLink) model.Risk {
	sourceAsset := model.ParsedModelRoot.TechnicalAssets[incomingFlow.SourceId]
	title := "<b>Clickjacking</b> risk at <b>" + technicalAsset.Title + "</b> via <b>" + incomingFlow.Title + "</b> from <b>" + sourceAsset.Title + "</b>"
	impact := model.LowImpact
	if incomingFlow.HighestIntegrity() == model.MissionCritical {
		impact = model.MediumImpact
	}
	risk := model.Risk{
		Category:                        CustomRiskRule.Category(),
		Severity:                        model.CalculateSeverity(model.Likely, impact),
		ExploitationLikelihood:          model.Likely,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantCommunicationLinkId: incomingFlow.Id,
		DataBreachProbability:           model.Improbable,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id + "@" + incomingFlow.Id + "@" + sourceAsset.Id
	return risk
}
