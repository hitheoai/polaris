"""Optional torch model. Importing the core SDK does not import this module."""

from __future__ import annotations

from typing import Any

import torch
from torch import Tensor, nn
from torch.nn import functional as F

from polaris.registry import CHECK_IDS


class ParallelDecisionModel(nn.Module):
    def __init__(self, encoder: nn.Module, hidden_size: int) -> None:
        super().__init__()
        self.encoder = encoder
        self.heads = nn.ModuleDict(
            {
                "norm": nn.LayerNorm(hidden_size),
                "risk": nn.Linear(hidden_size, len(CHECK_IDS)),
                "sufficiency": nn.Linear(hidden_size, len(CHECK_IDS)),
            }
        )

    def forward(self, input_ids: Tensor, attention_mask: Tensor) -> dict[str, Tensor]:
        hidden = self.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        mask = attention_mask.unsqueeze(-1).to(hidden.dtype)
        pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp_min(1.0)
        pooled = self.heads["norm"](pooled)
        return {
            "risk": self.heads["risk"](pooled).float(),
            "sufficiency": self.heads["sufficiency"](pooled).float(),
        }

    def freeze_encoder(self) -> None:
        self.encoder.requires_grad_(False)


def masked_loss_components(
    output: dict[str, Tensor], risk: Tensor, sufficiency: Tensor
) -> dict[str, tuple[Tensor, int]]:
    components = {}
    for name, targets in (("risk", risk), ("sufficiency", sufficiency)):
        known = targets >= 0
        if known.any():
            components[name] = (
                F.binary_cross_entropy_with_logits(
                    output[name][known], targets[known], reduction="sum"
                ),
                int(known.sum().item()),
            )
    return components


def masked_loss(output: dict[str, Tensor], risk: Tensor, sufficiency: Tensor) -> Tensor:
    components = masked_loss_components(output, risk, sufficiency)
    if not components:
        raise ValueError("a training batch must contain supervised targets")
    return torch.stack([total / count for total, count in components.values()]).sum()


class OptionScorer(nn.Module):
    """Experimental comparison; one independently encoded sequence per question."""

    def __init__(self, encoder: nn.Module, hidden_size: int) -> None:
        super().__init__()
        self.encoder = encoder
        self.scorer = nn.Sequential(nn.LayerNorm(hidden_size), nn.Linear(hidden_size, 1))

    def forward(
        self,
        input_ids: Tensor,
        attention_mask: Tensor,
        option_positions: Tensor,
        option_mask: Tensor,
    ) -> Tensor:
        if option_positions.ndim != 2 or option_positions.shape != option_mask.shape:
            raise ValueError("option positions and mask must align")
        if option_mask.dtype != torch.bool or option_positions.shape[0] != input_ids.shape[0]:
            raise ValueError("option masks must be boolean and match the input batch")
        if (option_mask.sum(dim=1) < 2).any():
            raise ValueError("every question needs at least two options")
        if (option_positions[option_mask] < 0).any() or (
            option_positions[option_mask] >= input_ids.shape[1]
        ).any():
            raise ValueError("option marker is outside its sequence")
        hidden = self.encoder(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        positions = (
            option_positions.masked_fill(~option_mask, 0)
            .unsqueeze(-1)
            .expand(-1, -1, hidden.shape[-1])
        )
        states = hidden.gather(1, positions)
        return self.scorer(states).squeeze(-1).float().masked_fill(~option_mask, -torch.inf)


def distillation_loss(
    student: dict[str, Tensor],
    teacher: dict[str, Tensor],
    risk: Tensor,
    sufficiency: Tensor,
    *,
    temperature: float = 2.0,
    supervised_weight: float = 0.75,
) -> Tensor:
    if temperature <= 0 or not 0 <= supervised_weight <= 1:
        raise ValueError("invalid distillation parameters")
    supervised = masked_loss(student, risk, sufficiency)
    soft = (
        torch.stack(
            [
                F.binary_cross_entropy_with_logits(
                    student[name] / temperature,
                    torch.sigmoid(teacher[name].detach() / temperature),
                )
                for name in ("risk", "sufficiency")
            ]
        ).sum()
        * temperature**2
    )
    return supervised_weight * supervised + (1 - supervised_weight) * soft


def model_parameter_counts(model: nn.Module) -> dict[str, Any]:
    parameters = sum(parameter.numel() for parameter in model.parameters())
    trainable = sum(
        parameter.numel() for parameter in model.parameters() if parameter.requires_grad
    )
    return {
        "parameters": parameters,
        "trainable_parameters": trainable,
        "fp32_weight_bytes_only": parameters * 4,
        "not_peak_process_memory": True,
    }
