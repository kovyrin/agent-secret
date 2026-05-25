# Agent Secret Public Launch Plan

Status: Draft
Last updated: 2026-05-25
Owner: Oleksiy Kovyrin
Primary repo: [kovyrin/agent-secret][repo]

## Goal

Launch Agent Secret publicly as a useful personal tool for hackers who use
coding agents, macOS, and 1Password. The goal is not a commercial campaign. The
goal is to make the tool discoverable, understandable, installable, and
credible enough that other people try it when they hit the same problem.

Success looks like:

- Developers install it and run at least one real `agent-secret exec` flow.
- The launch produces useful GitHub issues, questions, and design feedback.
- The docs and demo make the security boundary clear without overselling it.
- People understand that this is already used daily by a real team.

## Core Positioning

One sentence:

> Agent Secret is a local macOS secret access approval broker for coding agents.

Short pitch:

> Agent Secret lets coding agents request exact access to exact 1Password references,
> shows you a native approval prompt with the command and reason, then injects approved
> values only into the agent's child process.

Personal story:

> We have been using Agent Secret on a 5-person team for about a month. On busy
> days it handles dozens of approvals, probably up to 50, across personal,
> employee, and shared team vaults. Even after this short period, I cannot imagine
> going back to raw `op` prompts now. That would mean giving up the request context
> we now rely on: which agent is asking, what it wants to read, why it needs it,
> and what command will receive the values.

## Problem Narrative

We are a team that uses AI agents heavily for real work. Useful agents need
access to real systems: deploy hooks, databases, cloud APIs, SaaS admin
surfaces, internal tools, and personal/team credentials. The more useful the
agent fleet becomes, the more dangerous it is to give it broad ambient access.

Moving secrets into 1Password helped because `op` can gate access on Touch ID.
That is a good primitive, but it does not carry enough intent once many agents
are running in parallel. A random Touch ID prompt for 1Password access stops
being meaningful when you cannot tell which agent triggered it, what it plans
to read, why it needs those refs, and what command will receive the values.

Agent Secret was built to make those approval moments intelligible. Agents ask
for specific refs, attach a reason, and show the command they intend to run.
The approval prompt becomes both a security checkpoint and a progress signal:
it tells the human where the agent is going, and it creates a natural
opportunity to deny or steer the work if the request does not make sense.

This framing should lead the launch. It is more compelling than "a nicer
wrapper around `op`" because the actual problem is approval context at agent
fleet scale.

## Audience

Primary audience:

- Developers using coding agents on macOS.
- Developers who already use 1Password for team and personal secrets.
- Small teams replacing direct `op` usage in automation scripts.

Secondary audience:

- Security-minded developers who want approval records and bounded access
  instead of raw secret reads.
- Tool builders interested in local-first agent workflows.

Not the audience yet:

- Linux or Windows users.
- Teams that need central policy management.
- Users who need write/update support for secrets.
- Users who need cloud secret-manager support today.

## Current Product Scope

Supported for this launch:

- macOS on Apple Silicon.
- 1Password desktop app with SDK integration enabled.
- `agent-secret exec` for one approved child process.
- Project profiles in `agent-secret.yml` or `.agent-secret.yml`.
- Secret-safe item metadata inspection.
- Homebrew cask install and upgrade.
- GitHub release DMG and unattended install script.
- Bundled agent skill installation.

Explicit limits:

- macOS only.
- 1Password only.
- Exec only.
- No long sessions for arbitrary command sequences.
- No secret modification yet.
- No GCP Secret Manager support yet.
- No sandbox guarantee for an approved child process.

Future-roadmap notes worth mentioning:

- Secret modification is planned.
- GCP Secret Manager access and GCP token minting support is planned.
- Longer command-session support is intentionally not in the launch version.

## Launch URL And Domain

Decision: `agent-secret.sh` is registered and should be the primary public URL.

Use this launch URL stack:

1. `https://agent-secret.sh` as the public product URL.
2. GitHub repo as the primary install CTA from that page.
3. Blog article as the narrative launch post linked from the product URL.

Product Hunt can use a GitHub repo URL, but a small landing page is better. If
we launch on Product Hunt, prefer `https://agent-secret.sh` with the GitHub
repo, install command, demo video, limitations, and security model linked above
the fold.

Hosting tasks:

- Point DNS for `agent-secret.sh` at the chosen static hosting provider.
- Enable HTTPS and confirm the certificate is valid.
- Publish a minimal product page with install, demo, limitations, and security
  model links above the fold.
- Redirect `www.agent-secret.sh` to the apex domain or serve the same page.

## Distribution

Primary install path:

```bash
brew tap kovyrin/agent-secret https://github.com/kovyrin/agent-secret
brew install --cask agent-secret
agent-secret skill-install
agent-secret doctor
```

Secondary install paths:

- Release installer script from GitHub Releases.
- Manual DMG install for users who prefer GUI installation.

Before launch, verify:

- The latest public release is signed and notarized.
- The Homebrew cask points at that release.
- `brew install --cask agent-secret` works on a clean macOS user or VM.
- `agent-secret doctor` gives useful non-secret diagnostics.
- The README starts with the Homebrew path.
- The release notes explain the user-visible changes since early private use.

## Assets

Required:

- Logo or app icon.
- README screenshots:
  - Approval request.
  - Item metadata request.
  - 1Password SDK integration.
- Demo video, 45 to 90 seconds.
- Blog hero image or screenshot.
- X thread copy.
- LinkedIn post copy.
- HN submission title and human-written first comment.
- Product Hunt copy if we include Product Hunt in this wave.

Nice to have:

- Animated GIF for the README or Product Hunt gallery.
- A short terminal transcript showing `exec --dry-run --json`.
- A before/after snippet replacing `op run` with `agent-secret exec`.

## Logo Prompt

Use this with an image-generation model:

```text
Create a polished macOS app icon for "Agent Secret", a developer tool that
brokers local human approval before coding agents can access 1Password secrets.
Use an abstract vault, keyhole, command prompt, or agent-routing motif, but no
literal text. The icon should feel trustworthy, technical, and local-first, not
corporate or cartoonish. Avoid hacker hoodies, skulls, shields full of binary,
and generic padlock-only imagery. Use a dark graphite base with deep teal and
warm amber accents, subtle depth, crisp edges, and a distinctive silhouette that
remains readable at 32px. Square 1024x1024 app-icon composition.
```

Ask for 4 variants, then pick one and generate:

- 1024x1024 app icon.
- 512x512 social avatar.
- 240x240 Product Hunt thumbnail.
- Transparent-background mark for the README or blog.

## Demo Video

Target length: 45 to 90 seconds.

Recommended flow:

1. Show the problem: a script or agent workflow needs a secret.
2. Show why a generic 1Password approval is not enough context.
3. Show the config profile with `op://` refs, not values.
4. Run `agent-secret exec --profile ... -- <safe command>`.
5. Show the native approval prompt with command, reason, cwd, and refs.
6. Approve it.
7. Show the command succeeds without printing the secret.
8. End on Homebrew install and the GitHub repo URL.

Keep the video practical. Do not over-narrate the security model; link to the
threat model for that.

## Blog Article

Working title:

> Touch ID is not enough context for agent secret access

Alternative titles:

- Agent Secret: local approvals for coding-agent secrets
- How our team stopped wiring 1Password CLI calls into every agent workflow
- A month with Agent Secret
- Making AI-agent secret requests understandable

Recommended outline:

1. The hook: our team uses agents enough that random 1Password Touch ID prompts
   became meaningless.
2. The agent-access problem: to make agents useful, you must grant access to
   more systems; every extra credential increases blast radius.
3. Why 1Password and `op` were still not enough: Touch ID gates access but does
   not explain which agent is asking, which refs it wants, why it needs them,
   or what command will receive the values.
4. What Agent Secret adds: explicit refs, explicit reason, explicit command,
   local native approval, and metadata-only audit context.
5. The team usage: 5 people, dozens of approvals per day, many vaults, both
   automation and ad-hoc access.
6. The migration: profiles replaced direct `op` usage in automation, while
   ad-hoc secret access moved to Agent Secret too.
7. The steering benefit: approval prompts now reveal where a background agent
   is heading, which creates a chance to deny or redirect bad requests.
8. The security boundary: local approval broker, not a sandbox.
9. The limits: macOS, 1Password, exec-only, no writes yet.
10. The install path: Homebrew first.
11. The ask: try it, break it, file issues, steal the idea.

Recommended tone:

- Personal, concrete, and slightly opinionated.
- Do not sound like SaaS launch copy.
- Use "this solved my workflow" more than "this is the future".
- Be explicit that this is a hacker sharing a tool, not a commercial launch.

## Channel Plan

### X

Format:

- One launch post with video.
- One short thread with the problem, solution, usage proof, install command,
  limitations, and GitHub link.

Constraints:

- Keep the first post under 280 weighted characters.
- URLs count as 23 characters.
- Attached media counts as 0 characters in official clients.

Main job:

- Drive developers to the GitHub repo or blog post.

### LinkedIn

Format:

- One narrative post, 1,200 to 2,000 characters.
- Lead with the personal/team story.
- Include the install path or GitHub link near the end.

Constraint:

- LinkedIn posts allow up to 3,000 characters.

Main job:

- Reach people who use coding agents at work and have team secret workflows.

### Hacker News

Preferred submission:

- Submit the blog article if it is substantial.
- Use the GitHub repo only if the blog is not ready.

Potential title:

> Agent Secret: local approvals for coding-agent secrets

Show HN title if submitting the repo directly:

> Show HN: Agent Secret, a local approval broker for 1Password secrets

Rules:

- Do not solicit upvotes or comments.
- Do not post generated or AI-edited comments.
- The first comment should be written by Oleksiy in his own voice.

Main job:

- Get high-signal technical criticism.

### Product Hunt

Recommendation:

- Treat Product Hunt as wave 2 unless the landing page, video, logo, and gallery
  are all ready.

Needed fields:

- Name: Agent Secret
- Tagline: Local approvals for coding-agent secrets
- Pricing: Free
- Tags: Developer Tools, Security, Open Source
- URL: `https://agent-secret.sh`
- Thumbnail: 240x240
- Gallery: at least two 1270x760 images
- Video: YouTube URL if available
- Maker first comment

Rules:

- Ask for feedback, comments, and testing.
- Do not ask for upvotes.
- Schedule up to one month ahead only after the assets are ready.

Main job:

- Broaden discovery after the initial hacker/dev audience has reacted.

## Launch Sequence

### Prep

- Pull latest `main` before editing release or public docs.
- Configure `agent-secret.sh` DNS, HTTPS, and static hosting.
- Verify current release and Homebrew cask install.
- Confirm README, configuration docs, threat model, and release notes are
  launch-ready.
- Confirm `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md` are accurate.
- Add a public "known limitations" section if the README does not make limits
  obvious enough.
- Generate logo candidates.
- Record demo video.
- Draft blog article.
- Draft X and LinkedIn posts.
- Decide whether Product Hunt is wave 1 or wave 2.

### Launch Day

- Publish or refresh the latest GitHub release.
- Publish the blog article.
- Post X thread with video.
- Post LinkedIn narrative.
- Submit to HN if the article is strong enough.
- Watch GitHub issues, X replies, LinkedIn comments, and HN discussion.
- Respond quickly to install failures and security-boundary questions.
- Do not debate edge cases before confirming whether docs need a patch.

### Follow-Up

- Triage launch feedback into:
  - Bugs.
  - Docs fixes.
  - Security questions.
  - Platform requests.
  - Product ideas.
- Ship one small docs patch within 24 hours if repeated confusion appears.
- Publish a short follow-up if there is a meaningful fix or clarification.
- Decide whether to schedule Product Hunt after first feedback is absorbed.

## Public Readiness Checklist

- [ ] Latest release is signed, notarized, and published.
- [ ] `agent-secret.sh` resolves over HTTPS.
- [ ] `www.agent-secret.sh` redirects or serves the same page.
- [ ] Product page links to GitHub, install docs, demo, limitations, and threat
  model.
- [ ] Homebrew cask installs the latest release.
- [ ] Clean-machine install succeeds.
- [ ] `agent-secret doctor` succeeds or gives actionable diagnostics.
- [ ] One real `agent-secret exec` flow works without printing secrets.
- [ ] README install path matches the launch recommendation.
- [ ] README makes macOS and 1Password requirements obvious.
- [ ] README makes exec-only and no-write limits obvious.
- [ ] Threat model is linked from the README.
- [ ] Security contact path is clear.
- [ ] Blog article draft exists.
- [ ] Demo video is recorded.
- [ ] Logo is selected.
- [ ] X post and thread are drafted.
- [ ] LinkedIn post is drafted.
- [ ] HN title and human-written first comment are prepared.
- [ ] Product Hunt is either ready or explicitly deferred.

## Open Decisions

1. Static hosting provider:
   Recommended: use whichever path is fastest for `agent-secret.sh`; GitHub
   Pages, Cloudflare Pages, or the existing blog hosting are all acceptable.
2. Product Hunt timing:
   Recommended: wave 2 unless the landing page and gallery are ready.
3. Launch date:
   Pick a day when Oleksiy can spend several hours responding.
4. Blog scope:
   Recommended: personal usage story plus practical migration examples, not a
   generic product announcement.
5. Demo command:
   Pick a safe command that proves secret consumption without printing values.
6. Roadmap disclosure:
   Mention secret writes and GCP Secret Manager as planned, without promising a
   date.

## Source Notes

<!-- markdownlint-disable MD013 -->

- [X character counting][x-character-counting]
- [LinkedIn post and article limits][linkedin-limits]
- [Product Hunt launch preparation][product-hunt-prep]
- [Product Hunt sharing rules][product-hunt-sharing]
- [Hacker News guidelines][hn-guidelines]

<!-- markdownlint-enable MD013 -->

[repo]: https://github.com/kovyrin/agent-secret
[x-character-counting]: https://docs.x.com/fundamentals/counting-characters
[linkedin-limits]: https://www.linkedin.com/help/linkedin/answer/a522483
[product-hunt-prep]: https://www.producthunt.com/launch/preparing-for-launch
[product-hunt-sharing]: https://www.producthunt.com/launch/sharing-your-launch
[hn-guidelines]: https://news.ycombinator.com/newsguidelines.html
