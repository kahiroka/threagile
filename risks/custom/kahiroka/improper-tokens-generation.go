package main

import (
	"github.com/threagile/threagile/model"
	"strings"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "improper-tokens-generation",
		Title: "Improper Tokens Generation [Plugin]",
		Description: "Vulnerable access tokens/sessionids which are weakly generated or reused risks might arise.",
		Impact:     "If this risk is unmitigated, network attackers might be able to guess the tokens/settionids.",
		ASVS:       "V3 - Session Management Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
		Action:     "Properly generate tokens/sessionids",
		Mitigation: "Generate tokens/sessionids by using cryptographic secure random number generator and don't reuse them for other purposes.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Development,
		STRIDE:     model.Spoofing,
		DetectionLogic: "Processed data assets named or tagged with 'token' or 'sessionid'",
		RiskAssessment: "Depending on the total rating of the technical-assets and data-assets.",
		FalsePositives: "If the tokens/sessionids are properly generated, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        1270,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{}
}

func (r customRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope {
			for _, dataAssetId := range technicalAsset.DataAssetsProcessed {
				dataAsset := model.ParsedModelRoot.DataAssets[dataAssetId]
				isToken := strings.Contains(dataAsset.Id, "token") || strings.Contains(dataAsset.Id, "sessionid") ||
					dataAsset.IsTaggedWithAny("token") || dataAsset.IsTaggedWithAny("sessionid")
				if isToken {
					risks = append(risks, createRisk(technicalAsset, dataAsset))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, dataAsset model.DataAsset) model.Risk {
	impact := model.MediumImpact
	title := "<b>Tokens/sessionids</b> <b>" + dataAsset.Title + "</b> found at <b>" + technicalAsset.Title + "</b>"
	likelihood := model.Likely
	risk := model.Risk{
		Category:                        CustomRiskRule.Category(),
		Severity:                        model.CalculateSeverity(likelihood, impact),
		ExploitationLikelihood:          likelihood,
		ExploitationImpact:              impact,
		Title:                           title,
		MostRelevantTechnicalAssetId:    technicalAsset.Id,
		MostRelevantDataAssetId:         dataAsset.Id,
		//MostRelevantCommunicationLinkId: dataFlow.Id,
		DataBreachProbability:           model.Possible,
		DataBreachTechnicalAssetIDs:     []string{technicalAsset.Id},
	}
	risk.SyntheticId = risk.Category.Id + "@" + dataAsset.Id + "@" + technicalAsset.Id
	return risk
}
