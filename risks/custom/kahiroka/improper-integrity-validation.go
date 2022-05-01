package main

import (
	"github.com/threagile/threagile/model"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "improper-integrity-validation",
		Title: "Improper Integrity Validation [Plugin]",
		Description: "Tampering high integrity data-assets risks might arise. E.g. access token, application package",
		Impact:     "If this risk is unmitigated, network attackers might be able to bypass security control by tampering data-assets.",
		ASVS:       "V3.5 - Token-based Session Management",
		CheatSheet: "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-explicit-revocation-by-the-user",
		Action:     "Integrity validation to high integrity data-assets",
		Mitigation: "Validate data-assets integrity by using digital signature or MAC.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Development,
		STRIDE:     model.Tampering,
		DetectionLogic: "Received and processed high integrity data-assets",
		RiskAssessment: "Depending on the integrity rating of the transferred data-assets either medium or high risk.",
		FalsePositives: "If there is more than one candidate technical asset to verify integrity, this can be considered as a false positives.",
		ModelFailurePossibleReason: false,
		CWE:                        354,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{}
}

func (r customRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		if !technicalAsset.OutOfScope {
			outgoingFlows := technicalAsset.CommunicationLinks
			incomingFlows := model.IncomingTechnicalCommunicationLinksMappedByTargetId[technicalAsset.Id]
			for _, dataAssetId := range technicalAsset.DataAssetsProcessed {
				dataAsset := model.ParsedModelRoot.DataAssets[dataAssetId]
				isCritical := dataAsset.Integrity == model.Critical || dataAsset.Integrity == model.MissionCritical
				if isCritical {
					for _, incomingFlow := range incomingFlows {
						for _, sentDataAsset := range incomingFlow.DataAssetsSent {
							if dataAssetId == sentDataAsset {
								risks = append(risks, createRisk(incomingFlow, dataAsset, false))
							}
						}
					}
					for _, outgoingFlow := range outgoingFlows {
						for _, receivedDataAsset := range outgoingFlow.DataAssetsReceived {
							if dataAssetId == receivedDataAsset {
								risks = append(risks, createRisk(outgoingFlow, dataAsset, true))
							}
						}
					}
				}
			}
		}
	}
	return risks
}

func createRisk(dataFlow model.CommunicationLink, dataAsset model.DataAsset, isReverse bool) model.Risk {
	impact := model.MediumImpact
	source := model.ParsedModelRoot.TechnicalAssets[dataFlow.SourceId]
	target := model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
	if isReverse {
		source = model.ParsedModelRoot.TechnicalAssets[dataFlow.TargetId]
		target = model.ParsedModelRoot.TechnicalAssets[dataFlow.SourceId]
	}
	title := "<b>Improper Integrity Validation</b> to <b>" + dataAsset.Title + "</b> at <b>" + target.Title + "</b> from <b>" + source.Title + "</b>"
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
	risk.SyntheticId = risk.Category.Id + "@" + dataAsset.Id + "@" + target.Id + "@" + source.Id
	return risk
}
