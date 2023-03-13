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
title Project Timeline

section Background

    SCION protocols (WP1) :active, rev1, 2021-02-10, 3d
    Colibri (WP1) : rev2, after rev1, 3d
    Golang (WP1) : rev3, after rev2, 3d

section Design

    Design1 (WP2): des1, after rev3,14d
    Design2 (WP3): des2, after des1, 14d

section Implementation

    Implement Design1 (WP2): imp1, after des1, 14d
    Implement Design2 (WP3): imp2, after eval1, 14d

section Evaluation
     Evaluation1 (WP4): eval1, after imp1, 7d
     Evaluation2 (WP4): eval2, after imp2, 7d

section Documentation

   Create/Setup Thesis Project: doc1, 2021-02-09, 3d
   Rough Bibliography: doc2, after doc1, 7d
   Background (WP1): doc3, after rev3, 3d

   Design Documentation & Results: doc4, after eval1, 2d
   Simulation Setup doc: doc9, after imp2, 3d
   Evaluation Results: doc10, after eval2, 3d
   Intro/Motivation/Discussion/Conclusion: doc11, after doc10,7d
   Clean up Thesis: doc0, after doc11, 2021-08-08


section Overview

   Base: active, over2, 2021-02-08, 90d
   Stretch: over3, after over2, 2021-08-08
   Project Window: active, over1, 2021-02-08, 2021-08-08

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
