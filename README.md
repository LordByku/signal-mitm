## Important Information

- **Student**:
- **Advisors**:
- **Start date**:
- **Submission date**:

## Timeline

*This should contain the timeline, which can be defined as a Gantt chart using [mermaid](https://mermaid-js.github.io/mermaid/). See example below.*

```mermaid
gantt
dateFormat  M
axisFormat m %m
title Project Timeline

section Background

    MitM Literature review (WP1) :active, rev1, 01, 3d
    Signal protocol (WP1) : rev2, after rev1, 3d
    Signal MitM literature review (WP1) : rev3, after rev2, 3d

section Design

    Analysis of security guarantees (WP2): des1, after rev3,7d
    Research tools to build MitM-proxy (WP3): des2, after des1, 7d
    Define the modifications of the Android Signal client (WP3): des3, after des2, 7d

section Implementation

    Implement MitM-proxy (WP2): imp1, after des2, 14d
    Implement Design2 (WP3): imp2, after eval1, 14d

section Evaluation
     Evaluate potential threats and the potential effects of these threats (WP4): eval1, after imp1, 7d
     Evaluate the MitM proxy on different applications (WP4): eval2, after imp2, 7d
     Test against countermeasures against MitM attacks on the Signal Messenger : eval3, after eval1, 7d


section Documentation

   Create/Setup Thesis Project: doc1, 02, 3d
   Rough Bibliography: doc2, after doc1, 7d
   Background (WP1): doc3, after rev3, 3d

   Design Documentation & Results: doc4, after eval1, 2d
   Simulation Setup doc: doc9, after imp2, 3d
   Evaluation Results: doc10, after eval2, 3d
   Intro/Motivation/Discussion/Conclusion: doc11, after doc10,7d
   Clean up Thesis: doc0, after doc11, 07


section Overview

   Base: active, over2, 02, 90d
   Stretch: over3, after over2, 07
   Project Window: active, over1, 01, 07

```

## Directory Structure

- [`notes`](./notes/README.md) contains lab notebooks and weekly reports.
- `project description` contains the project description.
- [`resources`](./notes/README.md) contains important resources like datasets, papers, and books.
- `thesis` contains the final thesis report.

## Thesis

- *Start writing **early**.*
- *Read [document about academic writing](https://cloud.inf.ethz.ch/s/Sdn8DybyAxZbtw3) and follow the rules described therein.*

## Evaluation

Our evaluation and grading criteria are listed in the [evaluation.csv](evaluation.csv) file.
