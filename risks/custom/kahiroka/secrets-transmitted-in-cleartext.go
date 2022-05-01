package main

import (
	"github.com/threagile/threagile/model"
	"strings"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "secrets-transmitted-in-cleartext",
		Title: "Secrets Transmitted In Cleartext [Plugin]",
		Description: "Secrets transmitted in cleartext risks might arise.",
		Impact:     "If this risk is unmitigated, network attackers might be able to eavesdrop on secrets sent between components.",
		ASVS:       "V9 - Communication Verification Requirements",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
		Action:     "Encryption of Communication Links",
		Mitigation: "Apply transport layer encryption to the communication links.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Development,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "Data assets named or tagged with 'credential', 'password', 'passphrase', 'secret-key' or 'private-key' transferred via unencrypted communication links",
		RiskAssessment: "Depending on the confidentiality rating of the transferred data-assets.",
		FalsePositives: "When all sensitive data sent over the communication links is already fully encrypted on document or data level, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        319,
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
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			isEncrypted := dataFlow.Protocol.IsEncrypted()
			targetAsset := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
			if !isEncrypted && dataFlow.Protocol != model.LocalFileAccess && (!technicalAsset.OutOfScope || !targetAsset.OutOfScope) {
				for _, sentDataAsset := range dataFlow.DataAssetsSent {
					dataAsset := model.ParsedModelRoot.DataAssets[sentDataAsset]
					isSecret := _isSecret(dataAsset)
					if isSecret {
						risks = append(risks, createRisk(technicalAsset, dataFlow, dataAsset))
					}
				}
				for _, receivedDataAsset := range dataFlow.DataAssetsReceived {
					dataAsset := model.ParsedModelRoot.DataAssets[receivedDataAsset]
					isSecret := _isSecret(dataAsset)
					if isSecret {
						risks = append(risks, createRisk(technicalAsset, dataFlow, dataAsset))
					}
				}
			}
		}
	}
	return risks
}

func createRisk(technicalAsset model.TechnicalAsset, dataFlow model.CommunicationLink, dataAsset model.DataAsset) model.Risk {
	impact := model.HighImpact
	target := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
	title := "<b>Secrets</b> <b>" + dataAsset.Title + "</b> transmitted in cleartext via <b>" + dataFlow.Title + "</b> between <b>" + technicalAsset.Title + "</b> and <b>" + target.Title + "</b>"
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
	risk.SyntheticId = risk.Category.Id + "@" + dataAsset.Id + "@" + dataFlow.Id + "@" + technicalAsset.Id + "@" + target.Id
	return risk
}
