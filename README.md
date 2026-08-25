## Part 1: Code Assessment

**Duration:** 1.5 hours
**Format:** AI-Assisted Pair Programming

---

## Welcome

In this interview, you'll implement a core component of an API security testing engine. You'll work with an **AI assistant of your choice** (Claude, ChatGPT, Copilot - whatever you're comfortable with).

We're interested in:

- How you collaborate with the AI - what you ask it vs. what you do yourself
- How you review and iterate on output
- The quality of your design and code

You can ask the interviewer clarifying questions at any time,  treat them as your PM.

Any data that is missing, or requires resources that are not here - you can mock. use your judgement, we are not looking for a specific answer or code structure, we are looking for a clear understanding of your approach.

The existing spec and spec parser are just there to help you understand the requirements, you can use them, ignore them, or use your own mock data.

---

**In your PR description, include:**

- updated files
- exported AI conversation

At the end of the session or before any clear conversation, export your AI conversation as a text or markdown file and add it to the repo:

```
ai-conversation/
└── chat.md
```

We review this as part of the interview - it helps us understand how you approach and collaborate with AI.

## The Scenario

Radware's engine container runs automated security tests against customer APIs. We want to **externalize patterns into configurable rules** so that our security research team can add, modify, and version attack signatures without deploying new engine code.

> Your job is to build the core of this rule engine.

### What We Need

Given a directory of YAML rule files and an API endpoint, the engine should:

1. Load the rules
2. Figure out which rules apply to the endpoint
3. Modify the request according to a rule's mutations (a rule mutation is what the rule specifies to modify the request)
4. Determine if the response indicates a vulnerability

> The interviewer is your PM - ask them questions if anything is unclear.
>

**Expected usage:**

example run with sample data:
```
python main.py --rules ./rules --spec ./sample_specs/petstore.yaml
```

> **It’s not a long-running service.** It runs, produces output, and exits.
>

## What to Prioritize

We'd rather see a code **that runs end-to-end on the test data** with fewer features, than more code that doesn't execute. If you're running low on time, cut scope - don't leave broken code.

---

## **When You're Done**

Commit your work, push, and open a PR.
If git actions are not available for you, you can zip your code and submit it as an attachment.

---

## Notes

- The interviewer is your PM. Ask them anything you'd ask a PM in real life.
- Commit as you go — we like to see how your thinking evolved.

Good luck! 🚀
