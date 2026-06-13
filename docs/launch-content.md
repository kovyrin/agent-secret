# Agent Secret Launch Content

This document tracks launch copy drafts for Agent Secret. The first pass starts
with the blog post because the social posts should come from the same story.

## Blog Post Draft

Working title:

> Making 1Password accessible to coding agents: Touch ID is not enough

## The Problem

Over the past year of building software across multiple companies and a ton of
personal projects, I have noticed an uncomfortable reality: the more useful I
wanted my agents to be for my work, the more access I needed to give them. They
need API tokens, deploy credentials, database URLs, cloud accounts, webhook
secrets, and all the other pieces of plumbing that make up operational
complexity in modern software.

I've experimented a lot with different options for making it possible for agents
to act on my behalf without them having ambient access to a lot of secrets: from
`.env` files on disk, to encrypted Rails credentials, to 1Password accessed via
`op`. With each iteration, the situation felt better. Especially with 1Password,
which gives you a very important primitive: the operating system can stop and
ask for Touch ID before secrets are released. That was good. It meant a
background process could not silently pull sensitive values without human
approval.

Nevertheless, I was never fully comfortable, because I still did not really
control which secrets were being accessed. After I approved short-term access to
my vaults, there was always a risk of an agent doing something unexpected and
potentially exposing unrelated secrets, or using them in an unintended way.

When I am running one command in one terminal, a 1Password approval prompt is
usually meaningful enough. I know what I just ran and why the prompt appeared. I
know what I expect to happen next. That process quickly falls apart when there
are many agents running in parallel. At that point, a random Touch ID prompt
asking for 1Password access means nothing. I do not necessarily know which agent
triggered it. I do not know which secrets it wants. I do not know why it wants
them. I do not know what command will receive the values after I approve.

## What I Built

As agents became better at following instructions and using CLI tools, it became
clear that I did not have to accept the default shape of secret access. I could
give them a tool built for the approval flow I actually wanted instead of asking
them to use `op` directly.

That is why I built Agent Secret: a local approval broker for coding-agent
secrets on macOS. It sits on top of 1Password and makes the request explicit:
which secrets an agent wants, why it wants them, and which command will receive
the values.

Instead of an agent running `op` directly, it asks Agent Secret to run a specific
command with a specific set of 1Password references. The request includes a
reason. The native macOS approval prompt shows the command, the working
directory, the provider account, and the exact secret references being
requested. Only after I approve does the child process receive the real values.

The difference sounds small, but it changes the trust boundary. I am no longer
approving a tool called `op` to talk to a vault. I am approving a particular
child process, in a particular directory, for a particular reason, with a
particular list of secret references. That is the decision I actually care about
when an agent is doing work in the background.

That changed the workflow more than I expected.

The approval prompt is no longer just an interruption. It is a compact status
report from the agent. It tells me what the agent is trying to do and why it
believes it needs secret access. If the request makes sense, I approve it. If it
does not, I deny it and steer the work before anything sensitive is released.

At work, our team has been using Agent Secret daily for months now. On busy days
it handles dozens of approvals across personal, employee, and shared team
vaults. Our automation uses Agent Secret profiles to get the credentials it
needs. Ad-hoc secret access goes through Agent Secret too. At this point, raw
`op` prompts feel like a huge step backward.

The other important part is that the expected secret access can live with the
project. Profiles turn "this workflow needs this token for this reason" into
configuration, not tribal knowledge in my head or a one-off command the agent
has to rediscover every time.

## Advanced Usage With Profiles

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

## Current Limitations

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

## Try it

Agent Secret is open source and installs through Homebrew:

```bash
brew tap kovyrin/agent-secret https://github.com/kovyrin/agent-secret
brew install --cask agent-secret
agent-secret skill-install
agent-secret doctor
```

The site is at <https://agent-secret.sh>, and the repository is at
<https://github.com/kovyrin/agent-secret>.

I built it for myself and we use it every day now. I am sharing it because I
think other people working seriously with agents are going to hit the same
problem, and I want them to have a better option when they do. If you like it,
[let me know](https://x.com/kovyrin).

## X Drafts

### Recommended Launch Post

Use this as the first post. Attach the demo video if you want the launch to show
the product immediately.

```text
As I've been using coding agents more and more, at some point random Touch ID
prompts for 1Password became meaningless.

So I built Agent Secret.

Agents say what they need, why they need it, and which command gets the values.
Then I approve or deny.

https://agent-secret.sh
```

### Blog Link Reply

Post this as a reply after the launch post if the blog post is already live.

```text
Longer write-up here. Why I built it, how we use it, and what it does not do
yet:

[BLOG_URL]
```

### Short Thread

Use this thread if you want the X launch to stand on its own without requiring
people to click through immediately.

```text
1/ I've been using coding agents more and more, and at some point random Touch
ID prompts for 1Password became meaningless.

So I built Agent Secret.

Agents say what they need, why they need it, and which command gets the values.
Then I approve or deny.

https://agent-secret.sh
```

```text
2/ Touch ID is great when I know what I just ran.

It gets much less useful when a few background agents are doing work and one of
them suddenly asks for 1Password access.

Which agent? Which secrets? Why? What gets the values?
```

```text
3/ Agent Secret sits between agents and 1Password.

Instead of calling `op` directly, an agent asks Agent Secret to run a specific
command with a specific set of 1Password references and a reason.
```

```text
4/ The useful part is not just "security".

The prompt is also a tiny status report from the agent. It shows what direction
the agent is moving in, and sometimes it gives me a chance to stop a weird path
before secrets are released.
```

```text
5/ We have been using this daily for months now across personal, employee, and
shared team vaults.

On busy days it handles dozens of approvals. At this point, raw `op` prompts
feel like a huge step backward.
```

```text
6/ It is intentionally limited right now:

macOS only
1Password only
single `exec` commands only
no secret writes yet

That is the shape I wanted for the first public version.
```

```text
7/ It is open source.

brew tap kovyrin/agent-secret https://github.com/kovyrin/agent-secret
brew install --cask agent-secret
agent-secret skill-install
agent-secret doctor
```

### Ready Replies

Use these if common questions show up while you are still around, or later when
you wake up.

```text
The main difference from `op` directly: I am approving a concrete command and a
concrete list of secrets, not just "some process wants 1Password".
```

```text
Very much v0 right now: macOS, 1Password, single `exec` commands. GCP Secret
Manager and writes are planned, but I wanted the first version to stay narrow.
```

```text
Profiles are what made it useful for us. The repo says which workflow needs
which token and why, so the agent does not have to rediscover that every time.
```
