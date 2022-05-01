package main

import (
	"github.com/threagile/threagile/model"
)

type customRiskRule string
var CustomRiskRule customRiskRule

func (r customRiskRule) Category() model.RiskCategory {
	return model.RiskCategory{
		Id:    "improper-ssh-fingerprint-validation",
		Title: "Improper SSH Fingerprint Validation [Plugin]",
		Description: "Improper SSH fingerprint validation risks might arise.",
		Impact:     "If this risk is unmitigated, network attackers might be able to perform MITM attack against SSH connections.",
		ASVS:       "V9 - Communication Verification Requirements",
		CheatSheet: "",
		Action:     "SSH fingerprint validation",
		Mitigation: "Validata the SSH fingerprint you're connecting to is a known one.",
		Check:      "Are recommendations from the linked cheat sheet and referenced ASVS chapter applied?",
		Function:   model.Development,
		STRIDE:     model.InformationDisclosure,
		DetectionLogic: "SSH communication links",
		RiskAssessment: "Depending on the confidentiality rating of the transferred data-assets either medium or high risk.",
		FalsePositives: "If the appropriate validation is implemented, this can be considered as a false positive.",
		ModelFailurePossibleReason: false,
		CWE:                        923,
	}
}

func (r customRiskRule) SupportedTags() []string {
	return []string{}
}

func (r customRiskRule) GenerateRisks() []model.Risk {
	risks := make([]model.Risk, 0)
	for _, technicalAsset := range model.ParsedModelRoot.TechnicalAssets {
		for _, dataFlow := range technicalAsset.CommunicationLinks {
			isSSH := dataFlow.Protocol == model.SSH || dataFlow.Protocol == model.SSH_tunnel
			sourceAsset := model.ParsedModelRoot.TechnicalAssets[dataFlow.SourceId]
			if !technicalAsset.OutOfScope || !sourceAsset.OutOfScope { // sourceAsset needed?
				if isSSH {
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
	title := "<b>Improper SSH fingerprint validation</b> at <b>" + technicalAsset.Title + "</b> via <b>" + dataFlow.Title + "</b> to <b>" + target.Title + "</b>"
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
	risk.SyntheticId = risk.Category.Id + "@" + technicalAsset.Id + "@" + dataFlow.Id + "@" + target.Id
	return risk
}
