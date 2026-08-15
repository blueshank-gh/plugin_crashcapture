# Contributing to Crash Capture

Hey there!\
This file covers how to report issues, submit pull requests, and what is expected of you as a contributor.\
It is short on purpose: the goal is a clean history and a reviewable diff, not a wall of process.

If you just want to fix something, the fastest path is:\
branch, make a focused change, rebase onto the latest master, open a pull request.

---

## Reporting issues

Before opening an issue, search the existing issues first. Duplicates are closed.

If you are reporting a crash or hang, read the report file first.\
Crash reports can contain private or sensitive server information, so sanitize anything sensitive before posting it.\
Do not paste raw captures or dump files!

### Bugs

A good bug report answers:

- What happened.
- What you expected to happen instead.
- Platform: OS and architecture (linux x86, linux x64, windows x86, windows x64).
- Plugin version and how it was loaded (`require`, source plugin, or sideload).
- How to reproduce it, if you know.
- Any relevant report content, sanitized.

Use the bug report template so nothing is missed.

### Crashes and hangs

- Do not paste raw crash captures that may contain private or sensitive server data, always sanitize first!
- Include the report reason line and, if present, the patches line from the report header (e.g. `3 applied, 1 drifted`)
  - That line tells us whether we are looking at engine behavior or at our own patches.

Use the crash report template.

### Feature requests

- Describe the problem you are trying to solve, not just a name for a feature you
  want.
- Crash Capture targets baseline Garry's Mod.
  - If your feature only makes sense on custom overrides or heavily modified builds, say so up front.

Use the feature request template.

---

## Submitting pull requests

The workflow that keeps this repository healthy, in order of importance:

1. **Never merge-after-pull.**

    Do not do `pull -> merge -> push`.\
    That leaves extra merge commits in the history.\
    Keep your clone up to date instead: `git fetch --all` then `git rebase origin/master`, resolve any conflicts, and push again.

2. **Always rebase your branch before merging it in a pull request.**

    Do not let a branch go stale.\
    Stale branches accumulate conflicts, and when several people are working on the project the conflicts only get worse.\
    Rebase routinely so the merge is a fast-forward with no surprises.

3. **Do not mix styling changes into a functional change.**

    No whitespace, tab, or spacing churn inside a bug fix or feature.\
    Keep the diff about the change so the history stays readable.\
    If the codebase genuinely needs a style change, do it in a dedicated branch and pull request of its own.

4. **Disclose and verify AI/LLM usage.**

    Limited AI use is allowed, but it must be disclosed and you must understand and stand behind the result.\
    See the AI usage policy below.

### Workflow

These aren't really a strict workflow, I don't expect people to just adopt these, but its a nice touch.

1. Create a branch off the latest `master`.

    Follow the existing naming convention:\
    `feature/#NN_slug` for features and `issue/#NN_slug` for bug fixes, using the issue number when one exists.

2. Make focused commits with clear messages.

    Commit messages use the `type - description` form, for example `feature - ...`, `patch - ...`, `improvement - ...`, or `milestone - ...`.

3. Rebase onto the latest `master` before opening the pull request.

    Just to prevent you from later on having to deal with a load of conflicts.

4. Verify the build.

    This is pretty important, because it gives a piece of mind that you know that something is working rather than finding out later.

5. Open the pull request using the template.
    Reference the issue it closes, e.g. `Closes #12`.

### What makes a good pull request

- One logical change per pull request, kept small.
- A description that explains the problem and the approach, not just what the code
  does.
- A branch that is rebased and not stale.
- No unrelated style or formatting changes.
- Verification: what you ran to confirm it works.

### What gets closed without comment

Pull requests, trackers, and issues that are primarily AI-generated, spammy, or
submitted without human verification are closed without further notice.\
However, this isn't an ultimate decision, we may respond back indicated as such before closing them or asking for them to be re-made.

---

## Labels

Beyond the standard GitHub labels (`bug`, `enhancement`, `question`, `help wanted`, `good first issue`, `duplicate`, `invalid`, `wontfix`, `documentation`), the repository uses these project-specific labels:

| Label | Meaning |
|---|---|
| `platform:linux` / `platform:windows` | The issue or PR is specific to that OS. |
| `architecture:x86` / `architecture:x64` | The issue or PR is specific to that build. |
| `arch-sensitive` | Involves architecture-breaking or architecture-changing features. |
| `refactor` | Changes a majority of the source code, higher risk of incompatibility. |
| `volatile` | Considered unstable and prone to breakage, treat with care. |
| `dependency` | Relates to a third-party dependency. |
| `type:lua` | Touches the Lua API or Lua-side behavior. |
| `type:engine` | Touches engine internals or interaction. |
| `type:physics` | Touches physics hooking or recovery. |
| `type:external` | Touches external tooling or integration (signals, processes, events). |
| `type:internal` | Touches internal parts of crash capture itself. |
| `type:binary` | Touches binary loading, build, or distribution. |

Add the relevant labels when you open an issue or pull request.\
`bug` and `enhancement` are applied automatically by the templates.

---

## AI / LLM usage policy

We allow limited AI/LLM usage as an assistive tool, not as a replacement for authorship, understanding, or review.

If AI/LLM tools were used during a contribution, that usage must be disclosed.\
We wouldn't want to end up in a situation where reviewers has to enforce this on contributors.\
Contributors are expected to understand, verify, and stand behind what they submit.

**Why this does this matter?**\
An LLM is only as good as the context it is given.\
Not enough context, or no human correction of a wrong assumption, and the output drifts from what is wanted.\
LLMs also over-produce: excessive comments, refactoring sections that do not
need it, and churn.\
The worst thing an LLM can do here is waste a reviewer's time on features or patches that are wrong or not needed at all.

### Allowed

- Explaining concepts and helping understand the codebase.
- Search and navigation of the codebase.
- Drafting documentation and inline function documentation that is reviewed and
  corrected by a human.
- Research and conceptualization of a feature.
- Assistance and code generation such as rewriting, summarizing, or brainstorming.

### Denied

- Hiding or lying about AI/LLM usage in contributions.
- Creating pull requests, trackers, or issues directly from AI output without proper
  human verification or understanding.
- Responding to reviewers using AI output.
  - This is the worst thing you can do...
- Submitting code, docs, or reports you cannot explain, maintain, or defend.

---

## Contributor responsibilities

- Understand, verify, and stand behind what you submit.
  - If you cannot explain it, you should not ship it.
- Keep your branch rebased and conflicts resolved.
- Review your own diff before opening a pull request.
- Be responsive to review feedback: discuss it, adjust the change, or explain why you disagree.
