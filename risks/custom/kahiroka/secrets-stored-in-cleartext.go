package main

import (
	"github.com/threagile/threagile/model"
	"strings"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "secrets-stored-in-cleartext",
		Title: "Secrets Stored In Cleartext [Plugin]",
		Description: "Secrets stored in cleartext risks might arise.",
		Impact:     "If this risk is unmitigated, attackers might be able to steal secrets.",
		ASVS:       "V2 - Authentication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
		Action:     "Hashing or encryption",
		Mitigation: "Hash secrets with salts for internal authentication or encrypt secrets for external ones.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Development,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "Stored data assets named or tagged with 'credential', 'password', 'passphrase', 'secret-key' or 'private-key'",
		RiskAssessment: "Depending on the confidentiality rating of the stored data-assets.",
		FalsePositives: "When all sensitive data is already fully encrypted, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        312,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{}
}

func _isSecret(dataAsset model.DataAsset) bool {
	isSecret := strings.Contains(dataAsset.Id, "credential") || strings.Contains(dataAsset.Id, "password") || strings.Contains(dataAsset.Id, "passphrase") ||
		strings.Contains(dataAsset.Id, "secret-key") || strings.Contains(dataAsset.Id, "private-key") ||
		dataAsset.IsTaggedWithAny("credential") || dataAsset.IsTaggedWithAny("password") || dataAsset.IsTaggedWithAny("passphrase") ||
		dataAsset.IsTaggedWithAny("secret-key") || dataAsset.IsTaggedWithAny("private-key")
	return isSecret
}

func (r customRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope {
			for _, dataAssetId := range technicalAsset.DataAssetsStored {
				dataAsset := model.ParsedModelRoot.DataAssets[dataAssetId]
				isSecret := _isSecret(dataAsset)
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
	title := "<b>Secrets</b> <b>" + dataAsset.Title + "</b> found at <b>" + technicalAsset.Title + "</b>"
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
