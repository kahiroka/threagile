package main

import (
	"github.com/threagile/threagile/model"
	"strings"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "sensitive-log-stored-in-cleartext",
		Title: "Sensitive Log Stored In Cleartext [Plugin]",
		Description: "Storing sensitive log in cleartest risks might arise.",
		Impact:     "If this risk is unmitigated, attackers might be able to steal sensitive information.",
		ASVS:       "V7.1 - Log Content Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
		Action:     "Assess the contents of the logs",
		Mitigation: "Remove or encrypt logs include sensitive information.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Development,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "Stored data assets named or tagged 'log'",
		RiskAssessment: "Depending on the confidentiality rating of the stored data-assets.",
		FalsePositives: "When all sensitive data stored in the logs is already fully encrypted, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        532,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{}
}

func (r customRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope {
			for _, dataAssetId := range technicalAsset.DataAssetsStored {
				dataAsset := model.ParsedModelRoot.DataAssets[dataAssetId]
				isSecret := strings.Contains(dataAsset.Id, "log") || dataAsset.IsTaggedWithBaseTag("log")
				if isSecret {
					risks = append(risks, createRisk(technicalAsset, dataAsset))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, dataAsset model.DataAsset) model.Risk {
	impact := model.HighImpact
	title := "<b>Debug log</b> " + dataAsset.Title + " found at <b>" + technicalAsset.Title + "</b>"
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
