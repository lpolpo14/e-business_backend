"""
Handles user input in regard to the CLI. Core components for handling input through interactive mode.
"""

import click
from typing import Dict, Any

from d3fender.input.inputParser import get_capabilities_defaults_from_registry, get_controls_defaults_from_registry, \
    apply_capabilities_from_controls


def interactive_input(capabilities_registry: Dict[str, Any],
                      controls_registry: Dict[str, Any],) -> Dict[str, Any]:
    """
    Builds the canonical input with the interactive mode.
    Args:
        capabilities_registry: The registry containing the capabilities.
        controls_registry: The registry containing the controls.

    Returns:
        The canonical representation of the organization's defenses and metadata.
    """
    capabilities = get_capabilities_defaults_from_registry(capabilities_registry)
    controls = get_controls_defaults_from_registry(controls_registry)

    click.secho("\nD3FENDer - Interactive Gap Detection", fg="cyan", bold=True)

    click.secho("Please answer the following questions using yes or no.\n", fg="white")

    click.secho("---Threat Context---", fg="cyan", bold=True)
    # Not optimal, but works and is logical.
    for capability in capabilities_registry.get('capabilities', []):
        capability_id = capability['id']

        if capability.get('category', "") != "context": # If capability is not context -> skip
            continue

        question = capability.get('interactive_text',
                                  f"Does your organization use {capability.get('title', capability_id)}")
        click.secho(question, fg="white", bold=True)
        capabilities[capability_id] = click.confirm("", default= capabilities.get(capability_id, False))

    click.secho("---Controls---", fg="yellow", bold=True)

    for control in controls_registry.get('controls', []):
        control_id = control['id']

        question = control.get('interactive_text', f"Does your organization use {control.get('title', control_id)}")
        click.secho(question, fg="white", bold=True)
        controls[control_id] = click.confirm("", default= controls.get(control_id, False))

    apply_capabilities_from_controls(controls, capabilities, controls_registry)

    click.secho("---Capabilities---", fg="green", bold=True)

    for capability in capabilities_registry.get('capabilities', []):
        capability_id = capability['id']

        if capabilities.get(capability_id, False) or capability.get('category', "") == "context": # If capability is enabled due to control.
            continue

        question = capability.get('interactive_text',
                                  f"Does your organization use {capability.get('title', capability_id)}")
        click.secho(question, fg="white", bold=True)
        capabilities[capability_id] = click.confirm("", default= capabilities.get(capability_id, False))

    click.secho("Thank you for your input.", fg="cyan")
    click.secho("-"*60, fg="white")

    return {"metadata": {"input_format": "interactive"},
            "threat_context": {},
            "capabilities": capabilities,
            "controls": controls,}