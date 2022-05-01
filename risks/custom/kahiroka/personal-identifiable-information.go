package main

import (
	"github.com/threagile/threagile/model"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "personal-identifiable-information",
		Title: "Personal Identifiable Information [Plugin]",
		Description: "Personal Idnetifiable Information (PII) disclosure risks might arise.",
		Impact:     "If this risk is unmitigated, network attackers might be able to steal PII.",
		ASVS:       "V8.3 - Sensitive Private Data",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html",
		Action:     "Encryption of PII",
		Mitigation: "Apply encryption to the PII",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Development,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "Data assets tagged with 'pii' or 'pii:eu'",
		RiskAssessment: "Depending on the confidentiality rating of the stored data-assets.",
		FalsePositives: "When all sensitive data stored in technical assets is already fully encrypted, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        359,
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
				if dataAsset.IsTaggedWithAny("pii:eu") {
					risks = append(risks, createRisk(technicalAsset, dataAsset, true))
				} else if dataAsset.IsTaggedWithBaseTag("pii") {
					risks = append(risks, createRisk(technicalAsset, dataAsset, false))
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, dataAsset model.DataAsset, gdpr bool) model.Risk {
	impact := model.HighImpact
	if gdpr {
		impact = model.VeryHighImpact
	}
	title := "<b>PII</b> <b>" + dataAsset.Title + "</b> found at <b>" + technicalAsset.Title + "</b>"
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
