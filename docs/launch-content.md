# Agent Secret Launch Content

This document tracks launch copy drafts for Agent Secret. The first pass starts
with the blog post because the social posts should come from the same story.

## Blog Post Draft

Working title:

> Making 1Password accessible to our coding agents: Simple Touch ID is not enough

Over the past year of building software across multiple companies and a ton of
personal projects, I have noticed an uncomfortable reality: the more useful I
wanted my agents to be for my work, the more access I needed to give them. They
need API tokens, deploy credentials, database URLs, cloud accounts, webhook
secrets, and all the other pieces of plumbing that make up operational
complexity of modern software.

I've experimented a lot with different options for making it possible for agents
to act on my behalf without them having ambient access to a lot of secrets: from
`.env` files on disk, to encrypted Rails credentials, to 1Password accessed via
`op`. With each iteration, the situation felt better. Especially with 1Password
which gives you a very important primitive: the operating system can stop and
ask for Touch ID before secrets are released. That was good, it meant a
background process could not silently pull sensitive values without a human
approval.

Nevertheless, I never felt comfortable knowing that I do not really control
which secrets are being accessed. So, there was always a risk of an agent doing
something unexpected and potentially exposing unrelated my secrets or using them
in an unintended way after I approved short-term access to my vaults.

When I am running one command in one terminal, a 1Password approval prompt is
usually meaningful enough. I know what I just ran and why the prompt appeared. I
know what I expect to happen next. That process quickly falls apart when there
are many agents running in parallel. At that point, a random Touch ID prompt
asking for 1Password access means nothing. I do not necessarily know which agent
triggered it. I do not know which secrets it wants. I do not know why it wants
them. I do not know what command will receive the values after I approve.

As agents became better at following instructions and using CLI tools, it became
clear, that I could potentially give them a custom tool that does exactly what I
want in terms of granting them access to my secrets (as opposed to the `op` tool
that is already in their training dataset). Ultimately, I ended up building
`agent-secret` - Agent Secret is a local approval broker for coding-agent
secrets on macOS sitting on top of 1Password and controlling what agents can
see, when, for how long, etc. It sits between the agent and 1Password and makes
the approval request explicit.

Instead of an agent running `op` directly, it asks Agent Secret to run a specific
command with a specific set of 1Password references. The request includes a
reason. The native macOS approval prompt shows the command, the working
directory, the provider account, and the exact secret references being
requested. Only after I approve does the child process receive the real values.

That changed the workflow more than I expected.

The approval prompt is no longer just an interruption. It is a compact status
report from the agent. It tells me what the agent is trying to do and why it
believes it needs secret access. If the request makes sense, I approve it. If it
does not, I deny it and steer the work before anything sensitive is released.

Our whole team has been using Agent Secret daily for months now. The tool
handles many dozens of approvals on busy days across personal, employee, and
shared team vaults. Our automation uses Agent Secret profiles to get the
credentials it needs. Ad-hoc agent secret access has moved through Agent Secret
as well. At this point, raw `op` prompts feel like a huge step backward.

The profile model is intentionally simple. A project can declare why a workflow
needs access and which environment variables should be populated from which
1Password references:

```yaml
version: 1
default_profile: terraform-cloudflare

profiles:
  terraform-cloudflare:
    reason: Terraform DNS management
    ttl: 10m
    secrets:
      CLOUDFLARE_API_TOKEN: op://Example/Cloudflare/token
```

Then an agent can run:

```bash
agent-secret exec --profile terraform-cloudflare -- terraform plan
```

The important part here is that the approval moment is now tied to a concrete
command, a concrete reason, and a concrete set of secret references.

This is also useful beyond pure security. It gives me another chance to
understand where a background agent is going. Sometimes the approval request is
the first sign that the agent is about to take a path I did not intend. That is
a good moment to intervene.

Since this is a new tool, there are still some real limits.

Agent Secret is macOS-only today. It only works with 1Password as the secret
source. The current implementation is focused only on single `exec` commands and
not long arbitrary shell sessions. It does not write or update secrets yet.

Those limits are deliberate. I wanted the first version to solve the approval
context problem with a minimal set of tools available to the agent.

If you are running coding agents with real credentials, especially on a team, I
think this is a useful primitive. Maybe you use Agent Secret directly. Maybe you
steal the idea and build it differently. Either way, I think agent secret access
needs to become more explicit than "a background process wants 1Password, tap
Touch ID to continue."

Agent Secret is open source and installs through Homebrew:

```bash
brew tap kovyrin/agent-secret https://github.com/kovyrin/agent-secret
brew install --cask agent-secret
agent-secret skill-install
agent-secret doctor
```

The site is at <https://agent-secret.sh>, and the repository is at
<https://github.com/kovyrin/agent-secret>.

I built it for myself and we use it every day now. I am sharing it because
I think other people working seriously with agents are going to quickly hit the
same problem and this approach may be helpful for some teams. If you like it,
let me know.

## X Drafts

TODO: derive the launch post and thread from the final blog draft.
