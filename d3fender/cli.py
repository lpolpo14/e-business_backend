"""
This file handles the command line interface. When the user starts the application and inputs his command,
this file acts like the gateway to the rest of the files.
"""


import click

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help']) # As documented in the official Click documentation

@click.group()
@click.version_option(package_name="d3fender") ## d3fender --version
def cli():
    """Security Assessment and Gap Detection CLI"""
    pass

@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("-f","--format", type=click.Choice(["json", "text"],case_sensitive=False),default="json", help="Input type")
@click.option("-F", "--file", type=click.File('r'), help="File from which set-up defenses are read",)
@click.option("-t", "--text", type=str,help="Input text given directly from the command line")
def assess(format, file, text):
    """D3FENDer is a Security Assessment and Gap Detection Tool developed by Michael Favvas"""

    if file and text:
        raise click.BadOptionUsage("Please either provide --file or --text")
    if not file and not text:
        raise click.BadParameter("Not input was given. Please either provide --file or --text")

    if file:
        content = file.read()
    else:
        content = text

    from d3fender.assessors.mainAssessor import runAssessment
    from d3fender.IO.Output import  render_findings

    findings = runAssessment(format,content)

    if not findings:
        click.echo("No security gaps were detected.")
        return

    rendered_findings = render_findings(findings)

    for rendered_finding in rendered_findings:
        click.echo(rendered_finding)
        click.echo("-"*60)



@cli.command(context_settings=CONTEXT_SETTINGS)
@click.option("-t", "technique",type=str, help="Get details about specific ATT&CK or D3FEND Technique")
def explain(technique):
    from d3fender.database.db_queries import getD3FENDTechnique, getATTACKTechnique, getATTACKTactic
    from d3fender.IO import Output as output
    if technique.startswith("D3-"):
        techniqueDetails = getD3FENDTechnique(technique)
        output.printD3FENDTechniqueToOutput(techniqueDetails)
    elif technique.startswith("T"):
        techniqueDetails = getATTACKTechnique(technique)
        if techniqueDetails is None:
            techniqueDetails = getATTACKTactic(technique)
        output.printATTACKTechniqueToOutput(techniqueDetails)
    else:
        raise click.BadParameter(f"Unknown technique {technique}")


# We are using poetry run script, therefore no need for this.
# if __name__ == "__main__":
#    cli()
