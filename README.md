## Important Information

- **Student**:
- **Advisors**:
- **Start date**:
- **Submission date**:

## Timeline

*This should contain the timeline, which can be defined as a Gantt chart using [mermaid](https://mermaid-js.github.io/mermaid/). See example below.*

```mermaid
gantt
dateFormat  YYYY-MM-DD
axisFormat m %m
title Project Timeline

section Background

    MitM Literature review (WP1) :done, rev1, 2023-01-01, 4d
    Signal protocol (WP1) : active, rev2, after rev1, 4d
    Signal MitM literature review (WP1) : done, rev3, after rev2, 4d

section Design

    Analysis of security guarantees (WP2): active, des1,2023-01-13,7d
    Research tools to build MitM-proxy (WP3): active, des2, 2023-01-17, 7d
    Define the modifications of the Android Signal client (WP3): des3, 2023-01-22, 7d

section Implementation

    Implement MitM-proxy (WP3): imp1, after des2, 30d

section Evaluation
     Evaluate potential threats and the potential effects of these threats (WP4): eval1, after imp1, 18d
     Evaluate the MitM proxy on different applications (WP4): eval2, 2023-03-13, 25d
     Test against countermeasures against MitM attacks on the Signal Messenger (WP5) : eval3, after eval1, 17d


section Documentation

   Create/Setup Thesis Project: done, doc1, 2023-01-05, 3d
   Rough Bibliography: active, doc2, after doc1, 10d
   Background (WP1): active, doc3, after rev3, 20d

   Design Documentation & Results (WP2 & WP3): doc4, after eval1, 15d
   Simulation Setup doc: doc9, after imp2, 7d
   Evaluation Results(WP4): doc10, after eval2, 15d
   Intro/Motivation/Discussion/Conclusion: doc11, after doc10,15d
   Clean up Thesis: doc0, after doc11, 2023-07-01


section Overview

   Base: active, over2, 2023-01-01, 120d
   Stretch: over3, after over2, 2023-07-14
   Project Window: active, over1, 2023-01-01 , 2023-07-14


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
