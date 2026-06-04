# Agent Secret Public Launch Plan

Status: Active tracker
Last updated: 2026-06-01
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

## Tracking Rules

- Keep the "Outstanding Work" section as the source of truth for what remains.
- Move completed one-time setup work into "Completed Work".
- Keep narrative, positioning, and channel notes as reference material only.
- Remove tasks when they stop being relevant; do not leave stale unchecked
  items in the main checklist.

## Completed Work

- [x] Public launch tracker created in this repository.
- [x] Primary launch domain registered: `agent-secret.sh`.
- [x] Homebrew-first distribution chosen.
- [x] Homebrew cask exists and currently points to `v0.0.13`.
- [x] GitHub release `v0.0.13` is published.
- [x] App icon selected, converted to transparent RGBA source, committed, and
  installed in the local dev build.
- [x] Core audience selected: developers using coding agents, macOS, and
  1Password.
- [x] Product scope and launch limits captured.
- [x] Blog narrative angle selected: Touch ID is not enough context for agent
  secret access.
- [x] Initial static product site built under `site/` with home, privacy, and
  terms pages.
- [x] Hosting target changed to Cloudflare Pages because `agent-secret.sh` DNS
  is already on Cloudflare.
- [x] Cloudflare Pages static headers, canonical redirects, robots.txt, and
  sitemap added to `site/`.
- [x] Cloudflare GitHub integration connected by Oleksiy.
- [x] Cloudflare Pages project `agent-secret` created from `kovyrin/agent-secret`.
- [x] Cloudflare Pages build config set to production branch `main`, no build
  command, and output directory `site`.
- [x] First Cloudflare Pages deployment completed successfully from commit
  `6c59827`.
- [x] `agent-secret.sh` attached as the Pages custom domain.
- [x] Proxied Cloudflare DNS records created for `agent-secret.sh` and
  `www.agent-secret.sh`.
- [x] `https://agent-secret.sh/`, `/privacy`, and `/terms` verified over HTTPS.
- [x] Native Cloudflare Single Redirect rule created for `www.agent-secret.sh`.
- [x] Temporary `www` redirect Worker removed.
- [x] `www.agent-secret.sh` detached from the Pages project and moved to a
  proxied placeholder DNS record.
- [x] `https://www.agent-secret.sh/` redirects to the apex domain with a 301
  native Cloudflare rule.
- [x] Repository-wide Agent Secret profile `cloudflare-pages` added for the
  Cloudflare Pages deploy token.
- [x] Cloudflare Pages build watch paths reset from `site/**` to `*`; the
  skipped Git deployment for `40c89b0` was retried and completed successfully.
- [x] Site deployment script added at `scripts/deploy-site.sh` to validate the
  `site/` tree, enforce Cloudflare Pages asset limits, push `main`, poll the
  Pages deployment, and verify live URLs through the repo Agent Secret profile.
- [x] Pages headers now send `Cache-Control: no-transform` so Cloudflare Email
  Obfuscation does not rewrite code examples.
- [x] Launch release `v0.0.13` with the final transparent icon was signed,
  notarized, verified locally, and published.
- [x] Homebrew cask updated to `v0.0.13`; audit, install, `skill-install`,
  `doctor`, and upgrade no-op checks passed.
- [x] A real `agent-secret exec` smoke using the Cloudflare Pages profile
  completed without printing the secret value.
- [x] Dedicated 1Password guest account and single-vault test secret selected
  for clean-machine validation.
- [x] macOS VM validation runbook and UTM clean-install runner added.
- [x] UTM clean-machine install drill passed against launch release `v0.0.13`
  with `doctor`, dry-run validation, and real approval smoke.
- [x] Published product page verified for GitHub, install, demo, limitations,
  privacy, terms, and threat-model links.
- [x] Public README, configuration docs, threat model, and security contact path
  reviewed for launch readiness.
- [x] Demo video recorded and added to the product page as a launch asset.
- [x] Demo video compressed without trimming so it fits Cloudflare Pages' 25 MiB
  per-file limit.

## Outstanding Work

### Launch Content

- [ ] Write the blog article.
- [ ] Draft the X launch post and thread.
- [ ] Draft the LinkedIn narrative post.
- [ ] Prepare the HN title and human-written first comment.
- [ ] Decide whether Product Hunt is wave 1 or wave 2.

### Product Hunt, If Wave 1

- [ ] Prepare 240x240 thumbnail.
- [ ] Prepare at least two 1270x760 gallery images.
- [ ] Prepare maker first comment.
- [ ] Create and schedule the Product Hunt launch.

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
to read, why it needs those secrets, and what command will receive the values.

Agent Secret was built to make those approval moments intelligible. Agents ask
for specific secrets, attach a reason, and show the command they intend to run.
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

Current state:

- `agent-secret.sh` is registered.
- Initial static site lives in `site/`.
- Privacy and terms pages exist for OAuth client setup.
- Cloudflare Pages is the selected host.
- Cloudflare deploys the `site/` directory from `main` with no build command.
- `https://agent-secret.sh/` is live.
- `https://www.agent-secret.sh/` redirects to `https://agent-secret.sh/` via a
  native Cloudflare redirect rule.

Product Hunt can use a GitHub repo URL, but a small landing page is better. If
we launch on Product Hunt, prefer `https://agent-secret.sh` with the GitHub
repo, install command, demo video, limitations, and security model linked above
the fold.

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

Current state:

- `v0.0.13` is published.
- The cask points at `v0.0.13`.
- The final app icon is included in the published launch release.

## Assets

Completed:

- App icon selected and committed at `scripts/build/assets/AppIcon.png`.
- README screenshots:
  - Approval request.
  - Item metadata request.
  - 1Password SDK integration.

Outstanding:

- Blog hero image or screenshot.
- X thread copy.
- LinkedIn post copy.
- HN submission title and human-written first comment.
- Product Hunt copy if we include Product Hunt in this wave.

Nice to have:

- Animated GIF for the README or Product Hunt gallery.
- A short terminal transcript showing `exec --dry-run --json`.
- A before/after snippet replacing `op run` with `agent-secret exec`.

## Demo Video

Recorded asset: 97 seconds, accepted as-is for launch and embedded on
`https://agent-secret.sh/#demo`.

Flow:

1. Show the problem: a script or agent workflow needs a secret.
2. Show why a generic 1Password approval is not enough context.
3. Show the config profile with `op://` references, not values.
4. Run `agent-secret exec --profile ... -- <safe command>`.
5. Show the native approval prompt with command, reason, cwd, and requested
   secrets.
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
   not explain which agent is asking, which secrets it wants, why it needs
   them, or what command will receive the values.
4. What Agent Secret adds: explicit secret references, explicit reason,
   explicit command, local native approval, and metadata-only audit context.
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
- Confirm `https://agent-secret.sh/` remains healthy after Cloudflare's domain
  status finishes moving from pending to active in the API.
- Confirm the `v0.0.13` release and Homebrew cask remain healthy after mirrors
  and local caches settle.
- Confirm README, configuration docs, threat model, and release notes are
  launch-ready.
- Confirm `LICENSE`, `SECURITY.md`, and `CONTRIBUTING.md` are accurate.
- Add a public "known limitations" section if the README does not make limits
  obvious enough.
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

Use this as a final launch gate only. Day-to-day tracking belongs in
"Outstanding Work".

- [x] Launch domain selected and registered.
- [x] App icon selected and committed.
- [x] Homebrew-first install path selected.
- [x] Base Homebrew cask exists.
- [x] Launch release with final icon is signed, notarized, and published.
- [x] Homebrew cask installs the launch release.
- [x] `agent-secret.sh` resolves over HTTPS.
- [x] `www.agent-secret.sh` redirects to the apex domain.
- [x] Product page links to GitHub, install docs, demo, limitations, and threat
  model.
- [x] Clean-machine install succeeds.
- [x] `agent-secret doctor` succeeds or gives actionable diagnostics.
- [x] One real `agent-secret exec` flow works without printing secrets.
- [x] README install path matches the launch recommendation.
- [x] README makes macOS and 1Password requirements obvious.
- [x] README makes exec-only and no-write limits obvious.
- [x] Threat model is linked from the README.
- [x] Security contact path is clear.
- [x] Blog article draft exists.
- [x] Demo video is recorded.
- [ ] X post and thread are drafted.
- [ ] LinkedIn post is drafted.
- [ ] HN title and human-written first comment are prepared.
- [ ] Product Hunt is ready or explicitly deferred.

## Open Decisions

1. Product Hunt timing:
   Recommended: wave 2 unless the landing page and gallery are ready.
2. Launch date:
   Pick a day when Oleksiy can spend several hours responding.
3. Blog scope:
   Recommended: personal usage story plus practical migration examples, not a
   generic product announcement.
4. Demo command:
   Pick a safe command that proves secret consumption without printing values.
5. Roadmap disclosure:
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
